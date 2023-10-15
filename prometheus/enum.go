package prometheus

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

type ExporterType uint64

const (
	CounterVec   ExporterType = 1
	Counter      ExporterType = 2
	GaugeVec     ExporterType = 4
	Gauge        ExporterType = 8
	HistogramVec ExporterType = 16
	Histogram    ExporterType = 32
	SummaryVec   ExporterType = 64
	Summary      ExporterType = 128
)

var PrometheusExporterTypeMap = map[string]uint64{ // todo: Populate this from API
	"counter_vec":   1 << 0, // 1
	"counter":       1 << 1, // 2
	"gauge_vec":     1 << 2, // 4
	"gauge":         1 << 3, // 8
	"histogram_vec": 1 << 4, // 16
	"histogram":     1 << 5, // 32
	"summary_vec":   1 << 6, // 64
	"summary":       1 << 7, // 128
}

var PrometheusExporterTypeMapInvert = InvertMap(PrometheusExporterTypeMap)

func FromPrometheusExporterType(t ExporterType) string {
	result, ok := PrometheusExporterTypeMapInvert[uint64(t)]
	if ok {
		return result
	}

	log.WithFields(log.Fields{
		"prometheus_exporter_type": t,
	}).Warn("incorrect_from_type")

	return ""
}

func ToPrometheusExporterType(sType string) ExporterType {
	result, ok := PrometheusExporterTypeMap[strings.ToLower(sType)]
	if ok {
		return ExporterType(result)
	}

	log.WithFields(log.Fields{
		"prometheus_exporter_type": sType,
	}).Warn("incorrect_to_type")

	return 0
}
