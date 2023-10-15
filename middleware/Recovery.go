package middlewares

import (
	"fmt"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

func Recovery(version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// avoid broken pipe crash here
				// if connect is broken, don't response
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						serr := strings.ToLower(se.Error())
						if strings.Contains(serr, "broken pipe") ||
							strings.Contains(serr, "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				errResp := NewError(ErrorPanic, fmt.Sprintf("Panic error: %v", err))

				url := c.Request.URL.Path
				if c.Request.URL.RawQuery != "" {
					url += "?" + c.Request.URL.RawQuery
				}

				log.WithFields(log.Fields{
					"ip":        c.ClientIP(),
					"method":    c.Request.Method,
					"url":       url,
					"body":      GetBodyString(c),
					"traceback": errResp.Traceback,
				}).Error("http_request")

				if !brokenPipe {
					c.JSON(errResp.ToStatusCode(), &Response{
						Version: version,
						Success: false,
						Result:  nil,
						Error:   errResp,
					})
				} else {
					c.Error(err.(error)) // nolint: errcheck
					c.Abort()
				}
			}
		}()

		c.Next()
	}
}
