package middlewares

import (
	"fmt"
	"net/http"

	json "github.com/chaowen112/go-lib/jsonutils"

	"github.com/chaowen112/go-lib/byteutils"
	"github.com/chaowen112/go-lib/timeutils"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultMaxPayloadSize = 8000
)

func GetBody(c *gin.Context) []byte {
	var body []byte
	if cb, ok := c.Get(gin.BodyBytesKey); ok {
		if cbb, ok := cb.([]byte); ok {
			body = cbb
		}
	}
	if body == nil && c.Request.Body != nil {
		body, _ = c.GetRawData()
	}

	return body
}

func GetBodyString(c *gin.Context) string {
	return byteutils.ToString(GetBody(c))
}

func GetRequestURL(c *gin.Context) string {
	path := c.Request.URL.Path
	raw := c.Request.URL.RawQuery

	// Log requests.
	url := path
	if raw != "" {
		url += "?" + raw
	}
	return url
}

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer.
		start := timeutils.UnixMilli()
		// Process request.
		c.Next()

		// Stop timer.
		end := timeutils.UnixMilli()
		elapsed := int((end - start) * 1000)

		statusCode := c.Writer.Status()

		var resp interface{}

		// Log the response of the non GET request.
		if c.Request.Method != http.MethodGet {
			contextKey := ContextKeyResp
			if statusCode >= http.StatusBadRequest {
				contextKey = ContextKeyErr
			}

			value, exists := c.Get(contextKey)
			if exists {
				resp, _ = json.MarshalToString(value)
			}
		}

		bodyString := GetBodyString(c)
		if len(bodyString) > DefaultMaxPayloadSize {
			bodyString = fmt.Sprintf("<request payload too long(>%v characters) for log>", DefaultMaxPayloadSize)
		}

		log.WithFields(log.Fields{
			"ip":          c.ClientIP(),
			"elapsed":     elapsed,
			"method":      c.Request.Method,
			"url":         GetRequestURL(c),
			"body":        bodyString,
			"status_code": statusCode,
			"resp":        resp,
		}).Info("http_request")
	}
}
