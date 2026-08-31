package embassy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type ackEnvelope struct {
	OK bool `json:"ok"`
}

// ResultHandler serves the analysis result callback and dispatches to
// Config.ResultHandler.
//
//	mux.Handle("/rootcause/result", emb.ResultHandler())
//
// Your handler MUST be idempotent — upsert by analysis_id or metadata, never
// blind-insert. An unexpected error is deliberately NOT an ack, so the host
// redelivers, and a redelivery outside the freshness window is a legitimate
// second dispatch.
func (e *Embassy) ResultHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}

		raw, err := io.ReadAll(io.LimitReader(r.Body, maxInvocationBytes))
		if err != nil {
			secret, selected := e.inboundSecret(nil)
			if selected {
				e.writeSigned(w, 400, refusalEnvelope{Error: wireError{Class: ClassInvalidRequest, Message: "request body could not be read"}}, secret)
			} else {
				e.writeUnsigned(w, http.StatusUnauthorized, refusalEnvelope{Error: wireError{Class: ClassBadSignature, Message: "signature missing or invalid"}})
			}
			return
		}

		status, payload, secret := e.receiveResult(r.Context(), raw, r.Header.Get(SignatureHeader))
		if secret == "" {
			e.writeUnsigned(w, status, payload)
			return
		}
		e.writeSigned(w, status, payload, secret)
	})
}

func (e *Embassy) receiveResult(ctx context.Context, raw []byte, signature string) (int, any, string) {
	secret, selected := e.inboundSecret(raw)
	if !selected {
		refusal := badSignature("signature missing or invalid")
		e.logRefusal(refusal, raw)
		return refusal.Status, refusalEnvelope{Error: wireError{Class: refusal.Class, Message: refusal.Message}}, ""
	}
	if !VerifySignature(signature, raw, secret) {
		refusal := badSignature("signature missing or invalid")
		e.logRefusal(refusal, nil)
		return refusal.Status, refusalEnvelope{Error: wireError{Class: refusal.Class, Message: refusal.Message}}, secret
	}

	var payload resultPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return e.resultRefusal(invalidRequest("body is not valid JSON"), secret)
	}
	var missing []string
	for field, value := range map[string]string{
		"analysis_id": payload.AnalysisID, "nonce": payload.Nonce, "issued_at": payload.IssuedAt,
	} {
		if value == "" {
			missing = append(missing, field)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return e.resultRefusal(invalidRequest("missing field(s): %s", strings.Join(missing, ", ")), secret)
	}

	// A stale issued_at is STILL a 409 here: idempotency relaxes the nonce rule,
	// never the freshness envelope.
	if err := checkFreshness(payload.IssuedAt, e.cfg.ClockSkew, e.cfg.Now()); err != nil {
		return e.resultRefusal(asError(err), secret)
	}
	unseen, err := recordNonce(payload.Nonce, e.cfg.NonceStore, e.cfg.ClockSkew)
	if err != nil {
		return e.resultRefusal(asError(err), secret)
	}
	if !unseen {
		// The host deliberately sends a STABLE nonce = run_id across redeliveries so
		// we can dedupe. A duplicate here is our own retry, absorbed with the same
		// signed 200 the first delivery got — refusing it would make the host retry
		// forever against a healthy Embassy.
		e.logger().Info("rootcause result redelivery acked", "analysis_id", payload.AnalysisID)
		return http.StatusOK, ackEnvelope{OK: true}, secret
	}

	// The nonce is consumed BEFORE dispatch so two concurrent redeliveries cannot
	// both reach the handler; a failed dispatch gives it back, or one transient
	// handler error would permanently drop the result behind a 200 ack.
	if err := e.dispatchResult(ctx, payload); err != nil {
		e.cfg.NonceStore.Delete(payload.Nonce)
		var refusal *Error
		if errors.As(err, &refusal) {
			return e.resultRefusal(refusal, secret)
		}
		e.logger().Error("rootcause result handler failed", "analysis_id", payload.AnalysisID, "error_type", typeName(err))
		return http.StatusInternalServerError, refusalEnvelope{Error: wireError{Class: ClassInternalError, Message: typeName(err)}}, secret
	}

	e.logger().Info("rootcause result dispatched",
		"analysis_id", payload.AnalysisID,
		"metadata_keys", sortedKeys(payload.Metadata),
		"ok", payload.Decline == nil,
	)
	return http.StatusOK, ackEnvelope{OK: true}, secret
}

// dispatchResult runs the customer handler under the configured timeout and
// converts a panic into an error, so a handler bug is a signed 500 the host will
// retry rather than a crashed process.
func (e *Embassy) dispatchResult(ctx context.Context, payload resultPayload) (err error) {
	handler := e.cfg.ResultHandler
	if handler == nil {
		return handlerError("ResultHandler is not configured")
	}

	defer func() {
		if r := recover(); r != nil {
			err = &panicError{value: r}
		}
	}()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- &panicError{value: r}
			}
		}()
		done <- handler(payload.toResult())
	}()

	timer := time.NewTimer(e.cfg.Timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return handlerError("result handler exceeded %s", e.cfg.Timeout)
	case <-ctx.Done():
		return handlerError("result delivery was canceled")
	}
}

func (e *Embassy) resultRefusal(refusal *Error, secret string) (int, any, string) {
	e.logRefusal(refusal, nil)
	return refusal.Status, refusalEnvelope{Error: wireError{Class: refusal.Class, Message: refusal.Message}}, secret
}
