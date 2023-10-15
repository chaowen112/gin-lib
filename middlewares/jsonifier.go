package middlewares

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetResp(c *gin.Context, value interface{}) {
	c.Set(ContextKeyResp, value)
}

func SetErr(c *gin.Context, err *Error) {
	c.Set(ContextKeyErr, err)
}

func Default404(c *gin.Context) {
	SetErr(
		c,
		NewError(
			ErrorNotFound,
			fmt.Sprintf("Could not find route for URL '%v'", c.Request.URL),
		),
	)
}

func Jsonifier(version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Process request.
		c.Next()

		resp := &Response{
			Version: version,
		}

		shouldJsonify := false
		statusCode := http.StatusOK

		// Jsonify the response.
		value, exists := c.Get(ContextKeyResp)
		if exists {
			resp.Success = true
			resp.Result = value
			resp.Error = nil
			shouldJsonify = true
		}

		value, exists = c.Get(ContextKeyErr)
		if exists {
			err := value.(*Error)
			statusCode = err.ToStatusCode()

			resp.Success = false
			resp.Result = nil
			resp.Error = value
			shouldJsonify = true
		}

		if shouldJsonify {
			c.JSON(statusCode, resp)
		}
	}
}
