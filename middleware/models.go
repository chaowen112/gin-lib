package middlewares

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

const (
	ContextKeyResp    = "resp"
	ContextKeyErr     = "err"
	ContextSpaceToken = "space_token"

	ErrorPanic            ErrorType = "ERROR_PANIC"
	ErrorParams           ErrorType = "ERROR_PARAMS"
	ErrorNotFound         ErrorType = "ERROR_NOT_FOUND"
	ErrorInvalid          ErrorType = "ERROR_INVALID"
	ErrorServer           ErrorType = "ERROR_SERVER"
	ErrorHeader           ErrorType = "ERROR_HEADER"
	ErrorPermissionDenied ErrorType = "ERROR_PERMISSION_DENIED"
)

var (
	dunno     = []byte("???")
	centerDot = []byte("·")
	dot       = []byte(".")
	slash     = []byte("/")

	HTTPErrorMap = map[ErrorType]int{
		// the relationship with error type and http return code
		ErrorInvalid:          http.StatusBadRequest,
		ErrorParams:           http.StatusBadRequest,
		ErrorPanic:            http.StatusInternalServerError,
		ErrorNotFound:         http.StatusNotFound,
		ErrorServer:           http.StatusInternalServerError,
		ErrorHeader:           http.StatusBadRequest,
		ErrorPermissionDenied: http.StatusForbidden,
	}
)

type Response struct {
	Version string      `json:"version"`
	Success bool        `json:"success"`
	Error   interface{} `json:"error,omitempty"`
	Result  interface{} `json:"result,omitempty"`
}

type Error struct {
	StatusCode *int      `json:"-"`
	Message    string    `json:"message"`
	Type       ErrorType `json:"type"`
	Traceback  string    `json:"traceback"`
}

type ErrorType string

// Common Error handler
func SetError(c *gin.Context, err error, _type ErrorType) {
	debug := viper.GetBool("debug")
	var errorContext *Error

	httpCode, ok := HTTPErrorMap[_type]

	// set default http error code
	if !ok {
		httpCode = http.StatusInternalServerError
	}

	if debug {
		errorContext = NewErrorWithStatusCodeAndTraceBack(
			httpCode,
			ErrorInvalid,
			err,
		)
	} else {
		errorContext = NewErrorWithStatusCode(
			httpCode,
			ErrorInvalid,
			err.Error(),
		)
	}

	SetErr(
		c,
		errorContext,
	)
}

func NewErrorWithStatusCode(statusCode int, _type ErrorType, message string) *Error {
	e := &Error{
		StatusCode: &statusCode,
		Type:       _type,
		Message:    message,
	}

	e.Traceback = e.stack(2)

	return e
}

func NewError(_type ErrorType, message string) *Error {
	e := &Error{
		Type:    _type,
		Message: message,
	}

	e.Traceback = e.stack(2)

	return e
}

func NewErrorWithTraceBack(_type ErrorType, err error) *Error {
	e := &Error{
		Type:      _type,
		Message:   err.Error(),
		Traceback: fmt.Sprintf("%+v", err),
	}

	return e
}

func NewErrorWithStatusCodeAndTraceBack(statusCode int, _type ErrorType, err error) *Error {
	e := &Error{
		StatusCode: &statusCode,
		Type:       _type,
		Message:    err.Error(),
		Traceback:  fmt.Sprintf("%+v", err),
	}

	return e
}

func (e *Error) ToStatusCode() int {
	if e.StatusCode != nil {
		return *e.StatusCode
	}

	switch e.Type {
	case ErrorPanic:
		return http.StatusInternalServerError
	case ErrorParams, ErrorInvalid:
		return http.StatusBadRequest
	case ErrorNotFound:
		return http.StatusNotFound
	}

	return http.StatusInternalServerError
}

// stack returns a nicely formatted stack frame, skipping skip frames.
func (e *Error) stack(skip int) string {
	buf := new(bytes.Buffer) // the returned data
	// As we loop, we open files and read them. These variables record the currently
	// loaded file.
	var lines [][]byte
	var lastFile string
	for i := skip; ; i++ { // Skip the expected number of frames
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		// Print this much at least.  If we can't find the source, it won't show.
		fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
		if file != lastFile {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				continue
			}
			lines = bytes.Split(data, []byte{'\n'})
			lastFile = file
		}
		fmt.Fprintf(buf, "\t%s: %s\n", e.function(pc), e.source(lines, line))
	}
	return buf.String()
}

// source returns a space-trimmed slice of the n'th line.
func (e *Error) source(lines [][]byte, n int) []byte {
	n-- // in stack trace, lines are 1-indexed but our array is 0-indexed
	if n < 0 || n >= len(lines) {
		return dunno
	}
	return bytes.TrimSpace(lines[n])
}

// function returns, if possible, the name of the function containing the PC.
func (e *Error) function(pc uintptr) []byte {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return dunno
	}
	name := []byte(fn.Name())
	// The name includes the path name to the package, which is unnecessary
	// since the file name is already included.  Plus, it has center dots.
	// That is, we see
	//	runtime/debug.*T·ptrmethod
	// and want
	//	*T.ptrmethod
	// Also the package path might contains dot (e.g. code.google.com/...),
	// so first eliminate the path prefix
	if lastslash := bytes.LastIndex(name, slash); lastslash >= 0 {
		name = name[lastslash+1:]
	}
	if period := bytes.Index(name, dot); period >= 0 {
		name = name[period+1:]
	}
	name = bytes.Replace(name, centerDot, dot, -1)
	return name
}
