//go:build http

package httpserver

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/EvilFreelancer/coddy-agent/internal/acp"
	"github.com/EvilFreelancer/coddy-agent/internal/config"
	"github.com/EvilFreelancer/coddy-agent/internal/llm"
	"github.com/EvilFreelancer/coddy-agent/internal/session"
)

// testPushBrowser is the receiving side of Web Push as a browser holds it: a
// P-256 key pair and an auth secret, and the decryption of RFC 8291.
type testPushBrowser struct {
	priv *ecdh.PrivateKey
	auth []byte
}

func newTestPushBrowser() (*testPushBrowser, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		return nil, err
	}
	return &testPushBrowser{priv: priv, auth: auth}, nil
}

func (b *testPushBrowser) p256dh() string {
	return base64.RawURLEncoding.EncodeToString(b.priv.PublicKey().Bytes())
}

func (b *testPushBrowser) authSecret() string { return base64.RawURLEncoding.EncodeToString(b.auth) }

// decrypt opens an aes128gcm body the way a browser does (RFC 8291 section 3).
func (b *testPushBrowser) decrypt(body []byte) ([]byte, error) {
	if len(body) < 21 {
		return nil, errors.New("body shorter than its header")
	}
	salt := body[:16]
	_ = binary.BigEndian.Uint32(body[16:20])
	idlen := int(body[20])
	if len(body) < 21+idlen {
		return nil, errors.New("body shorter than its key id")
	}
	senderPub, err := ecdh.P256().NewPublicKey(body[21 : 21+idlen])
	if err != nil {
		return nil, err
	}
	shared, err := b.priv.ECDH(senderPub)
	if err != nil {
		return nil, err
	}
	keyInfo := append(append([]byte("WebPush: info\x00"), b.priv.PublicKey().Bytes()...), senderPub.Bytes()...)
	prkKey, err := hkdf.Extract(sha256.New, shared, b.auth)
	if err != nil {
		return nil, err
	}
	ikm, err := hkdf.Expand(sha256.New, prkKey, string(keyInfo), 32)
	if err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, body[21+idlen:], nil)
	if err != nil {
		return nil, err
	}
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 || plain[i] != 0x02 {
		return nil, errors.New("no last-record delimiter")
	}
	return plain[:i], nil
}

// testPushService is a push service: it takes the requests a server makes and
// keeps them for the browser to open.
type testPushService struct {
	ts       *httptest.Server
	mu       sync.Mutex
	messages []testPushMessage
	arrived  chan struct{}
}

type testPushMessage struct {
	header http.Header
	body   []byte
}

func newTestPushService() *testPushService {
	p := &testPushService{arrived: make(chan struct{}, 16)}
	p.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.messages = append(p.messages, testPushMessage{header: r.Header.Clone(), body: body})
		p.mu.Unlock()
		p.arrived <- struct{}{}
		w.WriteHeader(http.StatusCreated)
	}))
	return p
}

func (p *testPushService) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.messages)
}

func (p *testPushService) wait(n int, within time.Duration) (testPushMessage, error) {
	deadline := time.After(within)
	for p.count() < n {
		select {
		case <-p.arrived:
		case <-deadline:
			return testPushMessage{}, fmt.Errorf("the push service received %d messages, want %d", p.count(), n)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.messages[n-1], nil
}

type mobilePushState struct {
	home    string
	ts      *httptest.Server
	srv     *Server
	mgr     *session.Manager
	sid     string
	name    string
	code    string
	cookie  *http.Cookie
	browser *testPushBrowser
	push    *testPushService

	// rec is what the server's goroutines write: one per scenario, so a late
	// decision of a finished scenario never touches the next one's state.
	rec      *mobilePushRecorder
	turnDone chan error
	turnOver chan struct{}
	notice   pushNotice
}

type mobilePushRecorder struct {
	mu        sync.Mutex
	outcome   string
	decisions []string
	decided   chan struct{}
}

func (s *mobilePushState) reset() {
	if s.ts != nil {
		// A failed scenario can leave a turn waiting for an answer. A turn
		// outlives its client by design, so it is stopped the way the web UI
		// stops one, and Close does not wait for it forever.
		if s.turnOver != nil && s.sid != "" {
			select {
			case <-s.turnOver:
			default:
				_, _, _ = s.do(http.MethodPost, "/coddy/sessions/"+s.sid+"/cancel", "", map[string]string{})
				select {
				case <-s.turnOver:
				case <-time.After(5 * time.Second):
				}
			}
		}
		s.ts.CloseClientConnections()
		s.ts.Close()
	}
	if s.push != nil {
		s.push.ts.Close()
	}
	if s.home != "" {
		_ = os.RemoveAll(s.home)
	}
	*s = mobilePushState{}
}

func (s *mobilePushState) openServer(name string) error {
	s.name = name
	rec := &mobilePushRecorder{decided: make(chan struct{}, 64)}
	s.rec = rec
	home, err := os.MkdirTemp("", "coddy-mobile-home-*")
	if err != nil {
		return err
	}
	s.home = home
	cfg := &config.Config{
		Agent:  config.Agent{Model: "openai/gpt-4o"},
		Models: []config.ModelEntry{{Model: "openai/gpt-4o", MaxTokens: 100, Temperature: 0.2}},
		Paths:  config.Paths{Home: home},
	}
	runner := func(ctx context.Context, st *session.State, prompt []acp.ContentBlock, snd acp.UpdateSender) (string, error) {
		text := strings.TrimSpace(promptBlocksText(prompt))
		st.AddMessage(llm.Message{Role: llm.RoleUser, Content: text})
		if !strings.Contains(text, "run") {
			return string(acp.StopReasonEndTurn), nil
		}
		res, err := snd.RequestPermission(ctx, acp.PermissionRequestParams{
			SessionID: st.ID,
			ToolCall: acp.PermissionToolCall{
				ToolCallID: "perm-1",
				Title:      "Run: run_command",
				Kind:       "run_command",
				Status:     "pending",
			},
			Options: []acp.PermissionOption{
				{OptionID: "allow", Name: "Allow", Kind: "allow_once"},
				{OptionID: "always", Name: "Allow always", Kind: "allow_always"},
				{OptionID: "reject", Name: "Reject", Kind: "reject_once"},
			},
		})
		if err != nil {
			return string(acp.StopReasonCancelled), err
		}
		rec.mu.Lock()
		if res != nil {
			rec.outcome = res.Outcome
		}
		rec.mu.Unlock()
		return string(acp.StopReasonEndTurn), nil
	}
	log := slog.New(slog.DiscardHandler)
	s.mgr = session.NewManager(cfg, noopSender{}, runner, log, home, nil)
	s.srv = New(cfg, s.mgr, log, home)
	s.srv.push.decided = func(kind string, targets int) {
		rec.mu.Lock()
		rec.decisions = append(rec.decisions, fmt.Sprintf("%s:%d", kind, targets))
		rec.mu.Unlock()
		select {
		case rec.decided <- struct{}{}:
		default:
		}
	}
	s.ts = httptest.NewServer(s.srv.Handler())
	res, err := s.mgr.HandleSessionNew(context.Background(), acp.SessionNewParams{CWD: home})
	if err != nil {
		return err
	}
	s.sid = res.SessionID
	return nil
}

// do sends a request as the computer (host "") or as the phone (the proxy's
// name, with the device cookie once it has one).
func (s *mobilePushState) do(method, path, host string, body any) (*http.Response, []byte, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.ts.URL+path, rd)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if host != "" {
		req.Host = host
		req.Header.Set("Origin", "http://"+host)
		if s.cookie != nil {
			req.AddCookie(s.cookie)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	return res, raw, err
}

func (s *mobilePushState) computerShowsCode() error {
	res, raw, err := s.do(http.MethodPost, "/coddy/devices/pairing", "", map[string]string{})
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("pairing code: %s %s", res.Status, raw)
	}
	var out struct {
		Code  string `json:"code"`
		URL   string `json:"url"`
		QRPNG string `json:"qr_png"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.Code == "" || !strings.HasSuffix(out.URL, "/#/pair/"+out.Code) || !strings.HasPrefix(out.QRPNG, "data:image/png;base64,") {
		return fmt.Errorf("pairing answer %s", raw)
	}
	s.code = out.Code
	return nil
}

func (s *mobilePushState) phonePairs(name string) error {
	res, raw, err := s.do(http.MethodGet, "/v1/models", name, nil)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("an unpaired phone got %s from /v1/models, want 401: %s", res.Status, raw)
	}
	res, raw, err = s.do(http.MethodPost, "/coddy/auth/pair", name, map[string]string{"code": strings.ToLower(s.code), "name": "Test phone"})
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("pairing: %s %s", res.Status, raw)
	}
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, deviceCookieBaseName) {
			s.cookie = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	if s.cookie == nil || !s.cookieIsHTTPOnly(res) {
		return fmt.Errorf("pairing set no HttpOnly device cookie: %v", res.Header.Values("Set-Cookie"))
	}
	res, raw, err = s.do(http.MethodGet, "/v1/models", name, nil)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("the paired phone got %s from /v1/models: %s", res.Status, raw)
	}
	return nil
}

func (s *mobilePushState) cookieIsHTTPOnly(res *http.Response) bool {
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, deviceCookieBaseName) {
			return c.HttpOnly && c.SameSite == http.SameSiteStrictMode
		}
	}
	return false
}

func (s *mobilePushState) phoneSubscribes() error {
	browser, err := newTestPushBrowser()
	if err != nil {
		return err
	}
	s.browser = browser
	s.push = newTestPushService()
	body := map[string]any{
		"endpoint": s.push.ts.URL + "/push/AbCdEf",
		"keys":     map[string]string{"p256dh": s.browser.p256dh(), "auth": s.browser.authSecret()},
		"device":   "phone-1",
		"lang":     "en",
	}
	res, raw, err := s.do(http.MethodPost, "/coddy/push/subscriptions", s.name, body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("subscribe: %s %s", res.Status, raw)
	}
	return nil
}

func (s *mobilePushState) tabHasAttention() error {
	res, raw, err := s.do(http.MethodPost, "/coddy/presence", "", map[string]any{"device": "desk-1", "attentive": true})
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("presence: %s %s", res.Status, raw)
	}
	return nil
}

func (s *mobilePushState) phoneSendsPrompt() error {
	s.turnDone = make(chan error, 1)
	s.turnOver = make(chan struct{})
	go func() {
		defer close(s.turnOver)
		body := map[string]any{"model": "agent", "input": "please run the tests", "stream": true}
		raw, _ := json.Marshal(body)
		req, err := http.NewRequest(http.MethodPost, s.ts.URL+"/v1/responses", bytes.NewReader(raw))
		if err != nil {
			s.turnDone <- err
			return
		}
		req.Host = s.name
		req.Header.Set("Origin", "http://"+s.name)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Coddy-Session-ID", s.sid)
		req.AddCookie(s.cookie)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			s.turnDone <- err
			return
		}
		defer func() { _ = res.Body.Close() }()
		out, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			s.turnDone <- fmt.Errorf("the turn answered %s: %s", res.Status, out)
			return
		}
		s.turnDone <- nil
	}()
	return nil
}

func (s *mobilePushState) receivesNotice(n int, kind, tool string, buttons bool) error {
	msg, err := s.push.wait(n, 10*time.Second)
	if err != nil {
		return err
	}
	if got := msg.header.Get("Content-Encoding"); got != "aes128gcm" {
		return fmt.Errorf("Content-Encoding %q", got)
	}
	if !strings.HasPrefix(msg.header.Get("Authorization"), "vapid t=") {
		return fmt.Errorf("Authorization %q", msg.header.Get("Authorization"))
	}
	if bytes.Contains(msg.body, []byte(kind)) || bytes.Contains(msg.body, []byte(s.sid)) {
		return fmt.Errorf("the push service could read the notice: %q", msg.body)
	}
	plain, err := s.browser.decrypt(msg.body)
	if err != nil {
		return fmt.Errorf("the browser could not open the push: %w", err)
	}
	var notice pushNotice
	if err := json.Unmarshal(plain, &notice); err != nil {
		return err
	}
	if notice.Kind != kind || notice.SessionID != s.sid || notice.URL != "/#/s/"+s.sid || notice.SentAt == 0 {
		return fmt.Errorf("notice %s", plain)
	}
	if tool != "" && !strings.Contains(notice.Body, tool) {
		return fmt.Errorf("notice body %q names no %q", notice.Body, tool)
	}
	if buttons {
		if notice.ToolCallID != "perm-1" || notice.Allow != "allow" || notice.Reject != "reject" {
			return fmt.Errorf("notice buttons %s", plain)
		}
		if msg.header.Get("Urgency") != "high" {
			return fmt.Errorf("Urgency %q for a permission", msg.header.Get("Urgency"))
		}
	}
	s.notice = notice
	return nil
}

func (s *mobilePushState) answer(option, host string) error {
	toolCall := "perm-1"
	if host != "" && s.notice.ToolCallID != "" {
		toolCall = s.notice.ToolCallID
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, raw, err := s.do(http.MethodPost, "/coddy/sessions/"+s.sid+"/permission", host, map[string]string{"toolCallId": toolCall, "optionId": option})
		if err != nil {
			return err
		}
		if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("answer: %s %s", res.Status, raw)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *mobilePushState) turnAllowed() error {
	select {
	case err := <-s.turnDone:
		if err != nil {
			return err
		}
	case <-time.After(10 * time.Second):
		return errors.New("the turn did not end")
	}
	s.rec.mu.Lock()
	defer s.rec.mu.Unlock()
	if s.rec.outcome != "allow" {
		return fmt.Errorf("the command was answered %q", s.rec.outcome)
	}
	return nil
}

// receivesNothing waits until the service decided on the permission and on
// the turn's end, then checks that neither went out.
func (s *mobilePushState) receivesNothing() error {
	deadline := time.After(10 * time.Second)
	for {
		s.rec.mu.Lock()
		n := len(s.rec.decisions)
		got := strings.Join(s.rec.decisions, ",")
		s.rec.mu.Unlock()
		if n >= 2 {
			if got != "permission:0,turn_finished:0" {
				return fmt.Errorf("decisions %s, want both skipped", got)
			}
			break
		}
		select {
		case <-s.rec.decided:
		case <-deadline:
			return fmt.Errorf("decisions so far: %s", got)
		}
	}
	if n := s.push.count(); n != 0 {
		return fmt.Errorf("the push service received %d messages", n)
	}
	return nil
}

func TestMobilePairingPushFeature(t *testing.T) {
	st := &mobilePushState{}
	suite := godog.TestSuite{
		Name: "mobile-pairing-push",
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			sc.Step(`^an open Coddy server that a proxy names "([^"]*)"$`, st.openServer)
			sc.Step(`^the computer shows a pairing code$`, st.computerShowsCode)
			sc.Step(`^the phone opens the pairing link under "([^"]*)"$`, st.phonePairs)
			sc.Step(`^the phone subscribes to pushes at a fake push service$`, st.phoneSubscribes)
			sc.Step(`^a tab of Coddy has the person's attention$`, st.tabHasAttention)
			sc.Step(`^the phone sends a prompt whose turn asks to run a command$`, st.phoneSendsPrompt)
			sc.Step(`^the push service receives a notice that decrypts to "permission" for "([^"]*)" with Allow and Reject$`, func(tool string) error {
				return st.receivesNotice(1, pushKindPermission, tool, true)
			})
			sc.Step(`^the phone answers "([^"]*)" from the notification$`, func(option string) error {
				return st.answer(option, st.name)
			})
			sc.Step(`^the computer answers "([^"]*)" in that tab$`, func(option string) error {
				return st.answer(option, "")
			})
			sc.Step(`^the turn ends with the command allowed$`, st.turnAllowed)
			sc.Step(`^the push service receives a notice that decrypts to "turn_finished"$`, func() error {
				return st.receivesNotice(2, pushKindTurnFinished, "", false)
			})
			sc.Step(`^the push service receives nothing$`, st.receivesNothing)
			sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
				st.reset()
				return ctx, nil
			})
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../features/mobile_pairing_push.feature"},
			TestingT: t,
			Output:   os.Stdout,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("mobile pairing and push feature failed")
	}
}
