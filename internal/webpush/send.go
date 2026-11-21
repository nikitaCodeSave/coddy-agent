package webpush

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Subscription is what a browser's PushSubscription hands over: the endpoint
// of its push service and the two keys of its "keys" member. The keys are
// base64, padded or not, in the URL-safe or the standard alphabet.
type Subscription struct {
	Endpoint string
	P256dh   string
	Auth     string
}

// Options are the RFC 8030 headers of one push.
type Options struct {
	// TTL is how long the push service keeps a message it cannot deliver yet,
	// sent in whole seconds; zero asks it to deliver now or drop the message.
	TTL time.Duration
	// Urgency is "very-low", "low", "normal" or "high"; empty sends no header,
	// which the push service reads as "normal".
	Urgency string
	// Topic, when set, makes the push service replace an undelivered message
	// of the same topic: at most 32 characters of the URL-safe base64
	// alphabet (TopicFromKey derives one from any key).
	Topic string
}

// Result is what the push service answered.
type Result struct {
	StatusCode int
	// Gone is true on 404 and 410: the subscription is dead and should be
	// deleted.
	Gone bool
	// RetryAfter is the wait a 429 asked for, zero when it named none.
	RetryAfter time.Duration
}

// Sender pushes messages signed with Keys. Client is required: Send never
// falls back to http.DefaultClient, so the caller decides the proxy and the
// timeouts. Now defaults to time.Now.
type Sender struct {
	Keys    *Keys
	Subject string
	Client  *http.Client
	Now     func() time.Time
}

const (
	topicAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	maxTopicLen   = 32
	// maxRetryAfter bounds the wait a push service can ask for.
	maxRetryAfter = 24 * time.Hour
)

// TopicFromKey derives a valid Topic from any key, such as a notice's tag:
// the same key always gives the same topic.
func TopicFromKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return b64.EncodeToString(sum[:])[:maxTopicLen]
}

// Send encrypts payload for sub and posts it to the subscription's push
// service. A 2xx answer is a success; any other answer returns its Result
// together with an error that names the status. Errors name the endpoint's
// origin only, never its path.
func (s *Sender) Send(ctx context.Context, sub Subscription, payload []byte, opts Options) (Result, error) {
	switch {
	case s.Client == nil:
		return Result{}, errors.New("webpush: sender has no HTTP client")
	case s.Keys == nil:
		return Result{}, errors.New("webpush: sender has no VAPID keys")
	}
	origin, err := endpointOrigin(sub.Endpoint)
	if err != nil {
		return Result{}, err
	}
	if err := opts.check(); err != nil {
		return Result{}, err
	}
	uaPublic, err := decodeKey(sub.P256dh)
	if err != nil {
		return Result{}, fmt.Errorf("webpush: p256dh key: %w", err)
	}
	authSecret, err := decodeKey(sub.Auth)
	if err != nil {
		return Result{}, fmt.Errorf("webpush: auth secret: %w", err)
	}
	body, err := Encrypt(payload, uaPublic, authSecret)
	if err != nil {
		return Result{}, err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	authorization, err := s.Keys.AuthorizationHeader(sub.Endpoint, s.Subject, now())
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("webpush: request to %s: %w", origin, stripURL(err))
	}
	req.Header.Set("TTL", strconv.FormatInt(int64(opts.TTL/time.Second), 10))
	if opts.Urgency != "" {
		req.Header.Set("Urgency", opts.Urgency)
	}
	if opts.Topic != "" {
		req.Header.Set("Topic", opts.Topic)
	}
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", authorization)
	resp, err := s.Client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("webpush: push to %s: %w", origin, stripURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // lets the connection be reused

	res := Result{StatusCode: resp.StatusCode}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return res, nil
	}
	res.Gone = resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone
	if resp.StatusCode == http.StatusTooManyRequests {
		res.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), now())
	}
	return res, fmt.Errorf("webpush: %s answered %d %s", origin, resp.StatusCode, http.StatusText(resp.StatusCode))
}

func (o Options) check() error {
	if o.TTL < 0 {
		return errors.New("webpush: TTL is negative")
	}
	switch o.Urgency {
	case "", "very-low", "low", "normal", "high":
	default:
		return fmt.Errorf("webpush: urgency %q is not very-low, low, normal or high", o.Urgency)
	}
	if len(o.Topic) > maxTopicLen || strings.Trim(o.Topic, topicAlphabet) != "" {
		return fmt.Errorf("webpush: topic %q is not at most %d characters of the URL-safe base64 alphabet", o.Topic, maxTopicLen)
	}
	return nil
}

// stripURL drops the URL a url.Error quotes, which carries the endpoint's
// path, and keeps the cause.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// parseRetryAfter reads a Retry-After value, delay-seconds or an HTTP date,
// as a wait from now, bounded by maxRetryAfter; anything else is zero.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(min(secs, int64(maxRetryAfter/time.Second))) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return min(t.Sub(now), maxRetryAfter)
	}
	return 0
}
