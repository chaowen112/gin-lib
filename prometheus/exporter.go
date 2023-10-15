package prometheus

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var defaultMetricPath = "/metrics"

const (
	Scope = "REQ_HOST"
)

// Standard default metrics
//
//	counter, counter_vec, gauge, gauge_vec,
//	histogram, histogram_vec, summary, summary_vec
var reqCnt = &Metric{
	ID:          "reqCnt",
	Name:        "requests_total",
	Description: "How many HTTP requests processed, partitioned by status code and HTTP method.",
	Type:        ToPrometheusExporterType("counter_vec"),
	Args:        []string{"status_code", "method", "host", "url", "scope"}}

var reqDur = &Metric{
	ID:          "reqDur",
	Name:        "request_duration_seconds",
	Description: "The HTTP request latencies in seconds.",
	Type:        ToPrometheusExporterType("histogram_vec"),
	Args:        []string{"status_code", "method", "host", "url", "scope"}}

var resSz = &Metric{
	ID:          "resSz",
	Name:        "response_size_bytes",
	Description: "The HTTP response sizes in bytes.",
	Type:        ToPrometheusExporterType("summary"),
}

var reqSz = &Metric{
	ID:          "reqSz",
	Name:        "request_size_bytes",
	Description: "The HTTP request sizes in bytes.",
	Type:        ToPrometheusExporterType("summary"),
}

var standardMetrics = []*Metric{
	reqCnt,
	reqDur,
	resSz,
	reqSz,
}

type RequestCounterURLLabelMappingFn func(c *gin.Context) string

// Metric is a definition for the name, description, type, ID, and
// prometheus.Collector type (i.e. CounterVec, Summary, etc) of each metric
type Metric struct {
	MetricCollector prometheus.Collector
	ID              string
	Name            string
	Description     string
	Type            ExporterType
	Args            []string
}

// Prometheus contains the metrics gathered by the instance and its path
type Prometheus struct {
	reqCnt        *prometheus.CounterVec
	reqDur        *prometheus.HistogramVec
	reqSz, resSz  prometheus.Summary
	router        *gin.Engine
	listenAddress string

	MetricsList []*Metric
	MetricsPath string

	ReqCntURLLabelMappingFn RequestCounterURLLabelMappingFn

	// gin.Context string to use as a prometheus URL label
	URLLabelFromContext string
}

// NewPrometheus generates a new set of metrics with a certain subsystem name
func NewPrometheus(customMetricsList ...[]*Metric) *Prometheus {
	metricsList := make([]*Metric, 0)

	if len(customMetricsList) > 1 {
		panic("Too many args. NewPrometheus( string, <optional []*Metric> ).")
	} else if len(customMetricsList) == 1 {
		metricsList = customMetricsList[0]
	}

	metricsList = append(metricsList, standardMetrics...)

	p := &Prometheus{
		MetricsList: metricsList,
		MetricsPath: defaultMetricPath,
		ReqCntURLLabelMappingFn: func(c *gin.Context) string {
			return c.Request.URL.String() // i.e. by default do nothing, i.e. return URL as is
		},
	}

	p.registerMetrics()

	return p
}

// SetListenAddress for exposing metrics on address. If not set, it will be exposed at the
// same address of the gin engine that is being used
func (p *Prometheus) SetListenAddress(address string) {
	p.listenAddress = address
	if p.listenAddress != "" {
		p.router = gin.Default()
	}
}

// SetListenAddressWithRouter for using a separate router to expose metrics. (this keeps things like GET /metrics out of
// your content's access log).
func (p *Prometheus) SetListenAddressWithRouter(listenAddress string, r *gin.Engine) {
	p.listenAddress = listenAddress
	if len(p.listenAddress) > 0 {
		p.router = r
	}
}

// SetMetricsPath set metrics paths
func (p *Prometheus) SetMetricsPath(e *gin.Engine) {

	if p.listenAddress != "" {
		p.router.GET(p.MetricsPath, prometheusHandler())
		p.runServer()
	} else {
		e.GET(p.MetricsPath, prometheusHandler())
	}
}

// SetMetricsPathWithAuth set metrics paths with authentication
func (p *Prometheus) SetMetricsPathWithAuth(e *gin.Engine, accounts gin.Accounts) {

	if p.listenAddress != "" {
		p.router.GET(p.MetricsPath, gin.BasicAuth(accounts), prometheusHandler())
		p.runServer()
	} else {
		e.GET(p.MetricsPath, gin.BasicAuth(accounts), prometheusHandler())
	}
}

func (p *Prometheus) runServer() {
	if p.listenAddress != "" {
		//nolint:errcheck
		go p.router.Run(p.listenAddress)
	}
}

// NewMetric associates prometheus.Collector based on Metric.Type
func NewMetric(m *Metric) prometheus.Collector {
	var metric prometheus.Collector
	switch m.Type {
	case CounterVec:
		metric = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: m.Name,
				Help: m.Description,
			},
			m.Args,
		)
	case Counter:
		metric = prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: m.Name,
				Help: m.Description,
			},
		)
	case GaugeVec:
		metric = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: m.Name,
				Help: m.Description,
			},
			m.Args,
		)
	case Gauge:
		metric = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: m.Name,
				Help: m.Description,
			},
		)
	case HistogramVec:
		metric = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: m.Name,
				Help: m.Description,
			},
			m.Args,
		)
	case Histogram:
		metric = prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name: m.Name,
				Help: m.Description,
			},
		)
	case SummaryVec:
		metric = prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: m.Name,
				Help: m.Description,
			},
			m.Args,
		)
	case Summary:
		metric = prometheus.NewSummary(
			prometheus.SummaryOpts{
				Name: m.Name,
				Help: m.Description,
			},
		)
	}
	return metric
}

func (p *Prometheus) registerMetrics() {

	for _, metricDef := range p.MetricsList {
		metric := NewMetric(metricDef)
		if err := prometheus.Register(metric); err != nil {
			log.WithError(err).Error(fmt.Sprintf("%s could not be registered in Prometheus", metricDef.Name))
		}
		switch metricDef {
		case reqCnt:
			p.reqCnt = metric.(*prometheus.CounterVec)
		case reqDur:
			p.reqDur = metric.(*prometheus.HistogramVec)
		case resSz:
			p.resSz = metric.(prometheus.Summary)
		case reqSz:
			p.reqSz = metric.(prometheus.Summary)
		}
		metricDef.MetricCollector = metric
	}
}

// Use adds the middleware to a gin engine.
func (p *Prometheus) Use(e *gin.Engine) {
	e.Use(p.HandlerFunc())
	p.SetMetricsPath(e)
}

// UseWithAuth adds the middleware to a gin engine with BasicAuth.
func (p *Prometheus) UseWithAuth(e *gin.Engine, accounts gin.Accounts) {
	e.Use(p.HandlerFunc())
	p.SetMetricsPathWithAuth(e, accounts)
}

// HandlerFunc defines handler function for middleware
func (p *Prometheus) HandlerFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.String() == p.MetricsPath {
			c.Next()
			return
		}

		start := time.Now()
		reqSz := computeApproximateRequestSize(c.Request)

		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		elapsed := float64(time.Since(start)) / float64(time.Second)
		resSz := float64(c.Writer.Size())

		url := p.ReqCntURLLabelMappingFn(c)

		if len(p.URLLabelFromContext) > 0 {
			u, found := c.Get(p.URLLabelFromContext)
			if !found {
				u = "unknown"
			}
			url = u.(string)
		}

		// Avoid recording 404's url since it will increase the cardinality of `url` label.
		if status == "404" {
			url = "/404"
		}

		p.reqDur.WithLabelValues(status, c.Request.Method, c.Request.Host, url, c.GetString(Scope)).Observe(elapsed)
		p.reqCnt.WithLabelValues(status, c.Request.Method, c.Request.Host, url, c.GetString(Scope)).Inc()

		p.reqSz.Observe(float64(reqSz))
		p.resSz.Observe(resSz)
	}
}

func prometheusHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

// From https://github.com/DanielHeckrath/gin-prometheus/blob/master/gin_prometheus.go
func computeApproximateRequestSize(r *http.Request) int {
	s := 0
	if r.URL != nil {
		s = len(r.URL.String())
	}

	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return s
}

func PromURLLabelMappingFn(c *gin.Context) string {
	return c.Request.URL.Path
}
