package embassy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Read caps. Every outbound response is read through a LimitReader, so a hostile
// or broken peer cannot make the app allocate without bound. They live in one
// table because the only way to judge a cap is against its siblings.
const (
	// apiReadLimit is the loosest: the generic API plane is whatever the host
	// exposes, and a legitimate call may page a sizeable export.
	apiReadLimit = 32 << 20
	// scriptReadLimit bounds an action script body and its JSON envelope. A script
	// is source code a human reviewed; megabytes of it is already a bug.
	scriptReadLimit = 8 << 20
	// signedPostReadLimit bounds the analysis-trigger and sent-message replies,
	// which are small acknowledgements.
	signedPostReadLimit = 1 << 20
	// tokenReadLimit bounds the OAuth token response, a few hundred bytes.
	tokenReadLimit = 1 << 20
)

// The two failure stages are distinguishable because each caller reports them
// under different codes: reaching the peer is an operator problem, an unreadable
// body is a protocol problem.
var (
	errHTTPTransport = errors.New("embassy: http request failed")
	errHTTPRead      = errors.New("embassy: http response could not be read")
)

// httpResult is one fully-read response. The body is drained and closed before it
// returns, so no caller can leak a connection.
type httpResult struct {
	Status int
	Header http.Header
	Body   []byte
}

// doHTTP performs one outbound request and reads at most limit bytes of the
// response. The context rides the request.
func doHTTP(client *http.Client, request *http.Request, limit int64) (httpResult, error) {
	response, err := client.Do(request)
	if err != nil {
		return httpResult{}, fmt.Errorf("%w: %w", errHTTPTransport, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return httpResult{}, fmt.Errorf("%w: %w", errHTTPRead, err)
	}
	return httpResult{Status: response.StatusCode, Header: response.Header, Body: body}, nil
}
