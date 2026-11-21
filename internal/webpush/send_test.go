package webpush

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// capturedPush is what the fake push service received.
type capturedPush struct {
	method, path string
	header       http.Header
	body         []byte
}

// fakePushService answers every push with status and extra headers and hands
// what it received to the test through the returned channel.
func fakePushService(t *testing.T, status int, extra http.Header) (*httptest.Server, <-chan capturedPush) {
	t.Helper()
	got := make(chan capturedPush, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read push body: %v", err)
		}
		got <- capturedPush{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body}
		for name, values := range extra {
			w.Header()[name] = values
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

var testNow = time.Unix(1_700_000_000, 0)

func testSender(t *testing.T, client *http.Client) *Sender {
	t.Helper()
	return &Sender{Keys: mustKeys(t), Subject: "mailto:ops@example.com", Client: client, Now: func() time.Time { return testNow }}
}

func TestSendDeliversAnEncryptedSignedPush(t *testing.T) {
	topic := TopicFromKey("sess_1:permission")
	for _, tc := range []struct {
		name        string
		opts        Options
		padded      bool // the keys in padded standard base64, as some clients send them
		wantHeaders map[string]string
	}{
		{
			name:        "every option",
			opts:        Options{TTL: time.Hour, Urgency: "high", Topic: topic},
			wantHeaders: map[string]string{"TTL": "3600", "Urgency": "high", "Topic": topic},
		},
		{
			name:        "no options",
			padded:      true,
			wantHeaders: map[string]string{"TTL": "0", "Urgency": "", "Topic": ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, got := fakePushService(t, http.StatusCreated, nil)
			s := testSender(t, srv.Client())
			b := newBrowser(t)
			sub := b.subscription(srv.URL + "/push/abc")
			if tc.padded {
				sub.P256dh = base64.StdEncoding.EncodeToString(b.key.PublicKey().Bytes())
				sub.Auth = base64.StdEncoding.EncodeToString(b.auth)
			}
			payload := []byte(`{"v":1,"kind":"permission","sessionId":"sess_1","title":"Coddy"}`)

			res, err := s.Send(context.Background(), sub, payload, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if res != (Result{StatusCode: http.StatusCreated}) {
				t.Fatalf("result = %+v, want a plain 201", res)
			}
			push := <-got
			if push.method != http.MethodPost || push.path != "/push/abc" {
				t.Fatalf("request = %s %s, want POST /push/abc", push.method, push.path)
			}
			tc.wantHeaders["Content-Encoding"] = "aes128gcm"
			tc.wantHeaders["Content-Type"] = "application/octet-stream"
			for name, want := range tc.wantHeaders {
				if got := push.header.Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			claims, key := verifyVAPID(t, push.header.Get("Authorization"))
			if key != s.Keys.PublicKeyBase64() {
				t.Errorf("k = %s, want the sender's key", key)
			}
			want := vapidClaims{Aud: srv.URL, Exp: testNow.Add(12 * time.Hour).Unix(), Sub: s.Subject}
			if claims != want {
				t.Errorf("claims = %+v, want %+v", claims, want)
			}
			plain, err := b.decrypt(push.body)
			if err != nil {
				t.Fatal(err)
			}
			if string(plain) != string(payload) {
				t.Fatalf("decrypted %q, want %q", plain, payload)
			}
		})
	}
}

func TestSendReadsTheAnswer(t *testing.T) {
	retryAt := testNow.Add(90 * time.Second).UTC().Format(http.TimeFormat)
	for _, tc := range []struct {
		name       string
		status     int
		retryAfter string
		wantGone   bool
		wantRetry  time.Duration
	}{
		{name: "200 is a success", status: http.StatusOK},
		{name: "202 is a success", status: http.StatusAccepted},
		{name: "404 is gone", status: http.StatusNotFound, wantGone: true},
		{name: "410 is gone", status: http.StatusGone, wantGone: true},
		{name: "429 in seconds", status: http.StatusTooManyRequests, retryAfter: "120", wantRetry: 2 * time.Minute},
		{name: "429 as a date", status: http.StatusTooManyRequests, retryAfter: retryAt, wantRetry: 90 * time.Second},
		{name: "429 without a wait", status: http.StatusTooManyRequests},
		{name: "429 with garbage", status: http.StatusTooManyRequests, retryAfter: "soon"},
		{name: "429 asking for years", status: http.StatusTooManyRequests, retryAfter: "999999999999", wantRetry: 24 * time.Hour},
		{name: "400 is a failure", status: http.StatusBadRequest},
		{name: "413 is a failure", status: http.StatusRequestEntityTooLarge},
		{name: "500 is a failure", status: http.StatusInternalServerError, retryAfter: "30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := http.Header{}
			if tc.retryAfter != "" {
				extra.Set("Retry-After", tc.retryAfter)
			}
			srv, _ := fakePushService(t, tc.status, extra)
			s := testSender(t, srv.Client())
			res, err := s.Send(context.Background(), newBrowser(t).subscription(srv.URL+"/push/secret-capability"), []byte("hi"), Options{TTL: time.Hour})
			want := Result{StatusCode: tc.status, Gone: tc.wantGone, RetryAfter: tc.wantRetry}
			if res != want {
				t.Errorf("result = %+v, want %+v", res, want)
			}
			if tc.status < 300 {
				if err != nil {
					t.Fatalf("err = %v on %d", err, tc.status)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), strconv.Itoa(tc.status)) || !strings.Contains(err.Error(), srv.URL) {
				t.Fatalf("err = %v, want one naming %d and %s", err, tc.status, srv.URL)
			}
			if strings.Contains(err.Error(), "secret-capability") {
				t.Fatalf("err %q quotes the endpoint's path", err)
			}
		})
	}
}

func TestSendRefusesBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	b := newBrowser(t)

	for _, tc := range []struct {
		name    string
		mutate  func(s *Sender, sub *Subscription, opts *Options, payload *[]byte)
		wantErr string
	}{
		{"no HTTP client", func(s *Sender, _ *Subscription, _ *Options, _ *[]byte) { s.Client = nil }, "no HTTP client"},
		{"no keys", func(s *Sender, _ *Subscription, _ *Options, _ *[]byte) { s.Keys = nil }, "no VAPID keys"},
		{"bad subject", func(s *Sender, _ *Subscription, _ *Options, _ *[]byte) { s.Subject = "ops@example.com" }, "subject"},
		{"plain http to a remote host", func(_ *Sender, sub *Subscription, _ *Options, _ *[]byte) {
			sub.Endpoint = "http://push.example.net/push"
		}, "not https"},
		{"negative TTL", func(_ *Sender, _ *Subscription, o *Options, _ *[]byte) { o.TTL = -time.Second }, "TTL"},
		{"unknown urgency", func(_ *Sender, _ *Subscription, o *Options, _ *[]byte) { o.Urgency = "urgent" }, "urgency"},
		{"topic too long", func(_ *Sender, _ *Subscription, o *Options, _ *[]byte) { o.Topic = strings.Repeat("a", 33) }, "topic"},
		{"topic outside the alphabet", func(_ *Sender, _ *Subscription, o *Options, _ *[]byte) { o.Topic = "a+b" }, "topic"},
		{"p256dh not base64", func(_ *Sender, sub *Subscription, _ *Options, _ *[]byte) { sub.P256dh = "!!!" }, "p256dh"},
		{"p256dh too short", func(_ *Sender, sub *Subscription, _ *Options, _ *[]byte) { sub.P256dh = "BCVxsr7N" }, "p256dh"},
		{"auth secret too short", func(_ *Sender, sub *Subscription, _ *Options, _ *[]byte) { sub.Auth = "BTBZMqHH" }, "auth secret"},
		{"payload over one push", func(_ *Sender, _ *Subscription, _ *Options, p *[]byte) { *p = make([]byte, MaxPlaintext+1) }, "exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSender(t, srv.Client())
			sub, opts, payload := b.subscription(srv.URL+"/push/abc"), Options{TTL: time.Hour}, []byte("hi")
			tc.mutate(s, &sub, &opts, &payload)
			res, err := s.Send(context.Background(), sub, payload, opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one naming %q", err, tc.wantErr)
			}
			if res != (Result{}) {
				t.Fatalf("result = %+v, want none", res)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the push service got %d requests, want none", n)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSendTransportErrorNamesTheOriginOnly(t *testing.T) {
	refused := errors.New("connection refused")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, refused })}
	s := testSender(t, client)
	_, err := s.Send(context.Background(), newBrowser(t).subscription("https://push.example.net/push/secret-capability"), []byte("hi"), Options{})
	if !errors.Is(err, refused) || !strings.Contains(err.Error(), "https://push.example.net") || strings.Contains(err.Error(), "secret-capability") {
		t.Fatalf("err = %v, want the cause and the origin without the path", err)
	}

	srv, _ := fakePushService(t, http.StatusCreated, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = testSender(t, srv.Client()).Send(ctx, newBrowser(t).subscription(srv.URL+"/push/secret-capability"), []byte("hi"), Options{})
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "secret-capability") {
		t.Fatalf("err = %v, want context.Canceled without the path", err)
	}
}

func TestTopicFromKey(t *testing.T) {
	a, b := TopicFromKey("sess_1:permission"), TopicFromKey("sess_1:turn")
	if a != TopicFromKey("sess_1:permission") || a == b {
		t.Fatalf("topics %q and %q: want stable per key and distinct across keys", a, b)
	}
	if err := (Options{Topic: a}).check(); err != nil || len(a) != 32 {
		t.Fatalf("topic %q (%d characters) is not valid: %v", a, len(a), err)
	}
}
