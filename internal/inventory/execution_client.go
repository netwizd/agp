package inventory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/netwizd/agp/internal/configmodel"
	"github.com/netwizd/agp/internal/helper"
	"github.com/netwizd/agp/internal/securityjournal"
)

const executionResponseLimit = helper.MaxRequestBytes + (4 << 10)

// ExecutionBaselineChallenge fetches a new installation-bound, single-use
// challenge. Root performs its own serving-generation observation before signing.
func (c *Client) ExecutionBaselineChallenge(ctx context.Context) (*helper.BaselineChallenge, error) {
	raw, err := c.executionPost(ctx, "/agent/v1/execution/baseline-challenges", struct{}{}, http.StatusCreated, 16<<10)
	if err != nil {
		return nil, err
	}
	var query helper.BaselineChallenge
	if decodeBounded(bytes.NewReader(raw), &query, 16<<10) != nil || query.NodeID != c.node || !executionBaselineChallengeValid(query) {
		return nil, fmt.Errorf("%w: execution baseline challenge", ErrInvalid)
	}
	return &query, nil
}

// ExecutionCapture submits a root-signed observation. The control plane must
// verify its root identity, unused challenge, expiry and current source pins.
func (c *Client) ExecutionCapture(ctx context.Context, capture helper.BaselineCapture) error {
	if c == nil || capture.APIVersion != helper.BaselineCaptureVersion || capture.Purpose != "verified_baseline_capture" || capture.Query.NodeID != c.node || !executionBaselineChallengeValid(capture.Query) || !configmodel.ValidID(capture.KeyID) || !executionSignatureShape(capture.Signature) {
		return ErrInvalid
	}
	_, err := c.executionPost(ctx, "/agent/v1/execution/baselines", capture, http.StatusNoContent, 0)
	return err
}

func executionBaselineChallengeValid(q helper.BaselineChallenge) bool {
	challenge, err := base64.RawURLEncoding.DecodeString(q.Challenge)
	issued, e1 := executionUTC(q.IssuedAt)
	expires, e2 := executionUTC(q.ExpiresAt)
	return q.APIVersion == helper.BaselineChallengeVersion && configmodel.ValidID(q.ID) && configmodel.ValidID(q.NodeID) && configmodel.ValidID(q.AuthorityID) && configmodel.ValidDigest(q.AnchorDigest) && q.AuthorityEpoch > 0 && q.AuthorityEpoch <= securityjournal.MaxUInt63 && err == nil && len(challenge) == 32 && base64.RawURLEncoding.EncodeToString(challenge) == q.Challenge && e1 == nil && e2 == nil && expires.After(issued) && expires.Sub(issued) <= helper.MaxBaselineChallengeTTL
}

// ExecutionPending uses the same installation-pinned mTLS transport and node
// identity as inventory. The response cannot select a destination or command.
func (c *Client) ExecutionPending(ctx context.Context) ([]helper.Request, error) {
	raw, err := c.executionPost(ctx, "/agent/v1/execution/tasks", struct{}{}, http.StatusOK, executionResponseLimit)
	if err != nil {
		return nil, err
	}
	var response struct {
		Items []json.RawMessage `json:"items"`
	}
	if decodeBounded(bytes.NewReader(raw), &response, executionResponseLimit) != nil || response.Items == nil || len(response.Items) > 1 {
		return nil, fmt.Errorf("%w: execution task response", ErrInvalid)
	}
	items := make([]helper.Request, 0, len(response.Items))
	for _, item := range response.Items {
		request, err := helper.Decode(bytes.NewReader(item))
		if err != nil || request.SignedPlan == nil || request.Task.NodeID != c.node {
			return nil, fmt.Errorf("%w: execution task binding", ErrInvalid)
		}
		items = append(items, *request)
	}
	return items, nil
}

// ExecutionAuthorize returns the exact closed response bytes. Only the root
// executor verifies the purpose-separated signature and current journal head;
// successful HTTPS transport by itself does not authorize an effect.
func (c *Client) ExecutionAuthorize(ctx context.Context, query helper.StartQuery) ([]byte, error) {
	if !executionQueryValid(query) {
		return nil, ErrInvalid
	}
	raw, err := c.executionPost(ctx, "/agent/v1/execution/start-proofs", query, http.StatusOK, 16<<10)
	if err != nil {
		return nil, err
	}
	var proof helper.StartProof
	if decodeBounded(bytes.NewReader(raw), &proof, 16<<10) != nil || proof.Query != query || !configmodel.ValidID(proof.KeyID) || proof.WriterEpoch == 0 || proof.WriterEpoch > securityjournal.MaxUInt63 || !executionSignatureShape(proof.Signature) {
		return nil, fmt.Errorf("%w: execution proof response", ErrInvalid)
	}
	checked, e1 := executionUTC(proof.CheckedAt)
	expires, e2 := executionUTC(proof.ExpiresAt)
	if e1 != nil || e2 != nil || !expires.After(checked) || expires.Sub(checked) > helper.MaxStartTTL {
		return nil, fmt.Errorf("%w: execution proof interval", ErrInvalid)
	}
	return raw, nil
}

// ExecutionRecord acknowledges delivery only for the documented 204 with an
// empty body. A lost response must retain the helper's durable outbox entry.
func (c *Client) ExecutionRecord(ctx context.Context, receipt helper.ExecutionReceipt) error {
	if c == nil || receipt.NodeID != c.node || receipt.APIVersion != helper.ExecutionReceiptVersion || receipt.Purpose != "local_execution_outcome" || !configmodel.ValidID(receipt.TaskID) || !configmodel.ValidID(receipt.ReceiptID) || !configmodel.ValidID(receipt.KeyID) || !configmodel.ValidDigest(receipt.RequestDigest) || !executionSignatureShape(receipt.Signature) {
		return ErrInvalid
	}
	_, err := c.executionPost(ctx, "/agent/v1/execution/receipts", receipt, http.StatusNoContent, 0)
	return err
}

func executionQueryValid(q helper.StartQuery) bool {
	challenge, err := base64.RawURLEncoding.DecodeString(q.Challenge)
	return q.APIVersion == helper.StartVersion && err == nil && len(challenge) == 32 && base64.RawURLEncoding.EncodeToString(challenge) == q.Challenge && configmodel.ValidDigest(q.RequestDigest) && configmodel.ValidDigest(q.InstallationDigest) && configmodel.ValidID(q.Head.AuthorityID) && q.Head.Epoch > 0 && q.Head.Epoch <= securityjournal.MaxUInt63 && q.Head.Sequence <= securityjournal.MaxUInt63 && (configmodel.ValidDigest(q.Head.Digest) || q.Head.Sequence == 0 && q.Head.Digest == "")
}

func executionSignatureShape(signature string) bool {
	b, err := base64.RawURLEncoding.DecodeString(signature)
	return err == nil && len(b) == 64 && base64.RawURLEncoding.EncodeToString(b) == signature
}

func executionUTC(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || t.IsZero() || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

func (c *Client) executionPost(ctx context.Context, path string, input any, status, limit int) ([]byte, error) {
	if c == nil || c.http == nil || ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) > 64<<10 {
		return nil, ErrInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	response, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: execution transport", ErrUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
		return nil, fmt.Errorf("%w: execution response status %d", ErrUnavailable, response.StatusCode)
	}
	if len(response.Header.Values("Content-Encoding")) != 0 {
		return nil, fmt.Errorf("%w: execution response encoding", ErrInvalid)
	}
	if status == http.StatusNoContent {
		// net/http suppresses bodies for 204. Reject an advertised payload too,
		// including transports which expose a malformed response body directly.
		lengthHeaders := response.Header.Values("Content-Length")
		if len(lengthHeaders) > 1 {
			return nil, fmt.Errorf("%w: execution receipt response", ErrInvalid)
		}
		if len(lengthHeaders) == 1 {
			length, err := strconv.ParseUint(lengthHeaders[0], 10, 63)
			if err != nil || length != 0 {
				return nil, fmt.Errorf("%w: execution receipt response", ErrInvalid)
			}
		}
		if response.ContentLength > 0 || len(response.TransferEncoding) != 0 {
			return nil, fmt.Errorf("%w: execution receipt response", ErrInvalid)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1))
		if err != nil || len(raw) != 0 {
			return nil, fmt.Errorf("%w: execution receipt response", ErrInvalid)
		}
		return nil, nil
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return nil, fmt.Errorf("%w: execution response content type", ErrInvalid)
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("%w: execution response content type", ErrInvalid)
	}
	for key, value := range parameters {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return nil, fmt.Errorf("%w: execution response JSON encoding", ErrInvalid)
		}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, fmt.Errorf("%w: execution response document", ErrInvalid)
	}
	return raw, nil
}
