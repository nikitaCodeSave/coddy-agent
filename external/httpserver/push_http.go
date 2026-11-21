//go:build http

package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/EvilFreelancer/coddy-agent/internal/acp"
	"github.com/EvilFreelancer/coddy-agent/internal/session"
)

const maxPushBodyBytes = 8 << 10

func (s *Server) registerPushRoutes() {
	s.mux.HandleFunc("GET /coddy/push/key", s.pushKeyGet)
	s.mux.HandleFunc("GET /coddy/push/subscriptions", s.pushSubscriptionsGet)
	s.mux.HandleFunc("POST /coddy/push/subscriptions", s.pushSubscriptionsPost)
	s.mux.HandleFunc("DELETE /coddy/push/subscriptions/{id}", s.pushSubscriptionDelete)
	s.mux.HandleFunc("POST /coddy/push/test", s.pushTestPost)
	s.mux.HandleFunc("POST /coddy/push/receipt", s.pushReceiptPost)
	s.mux.HandleFunc("POST /coddy/presence", s.presencePost)
}

// pushHome is the agent home the push keys and subscriptions live in.
func (s *Server) pushHome() string {
	if c := s.activeCfg(); c != nil {
		return c.Paths.Home
	}
	return ""
}

// requestPrincipal names who a request comes from: the account of the
// sign-in form, a Telegram admin, a paired device, a bearer token, or the open
// local server.
func (s *Server) requestPrincipal(r *http.Request) string {
	if sess, ok := s.sessionFromRequest(r, s.loginPolicyNow()); ok {
		return "user:" + sess.User
	}
	if sess, ok := s.telegramSessionFromRequest(r); ok {
		return sess.User
	}
	if dev, ok := s.deviceFromRequest(r); ok {
		return "device:" + dev.ID
	}
	if bearerToken(r) != "" {
		return "token"
	}
	return "local"
}

func (s *Server) pushKeyGet(w http.ResponseWriter, r *http.Request) {
	if !s.push.enabled() {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}
	key, err := s.push.publicKey()
	if err != nil {
		s.log.Warn("push key unavailable", "error", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": true, "publicKey": key})
}

type pushSubscriptionBody struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	Device string `json:"device"`
	Lang   string `json:"lang"`
}

func (s *Server) pushSubscriptionsPost(w http.ResponseWriter, r *http.Request) {
	if !s.push.enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"error": "push needs an agent home"})
		return
	}
	var body pushSubscriptionBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPushBodyBytes)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}
	endpoint := strings.TrimSpace(body.Endpoint)
	if msg := validPushEndpoint(endpoint); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": msg})
		return
	}
	if !validPushKey(body.Keys.P256dh, 65) || !validPushKey(body.Keys.Auth, 16) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "keys.p256dh and keys.auth are required"})
		return
	}
	rec, err := s.push.subscribe(pushSubscriptionRecord{
		Endpoint:  endpoint,
		P256dh:    strings.TrimSpace(body.Keys.P256dh),
		Auth:      strings.TrimSpace(body.Keys.Auth),
		Principal: s.requestPrincipal(r),
		Device:    limitText(body.Device, 64),
		Lang:      limitText(body.Lang, 16),
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": err.Error()})
		return
	}
	s.log.Info("push subscription stored", "device", rec.Device, "origin", endpointOrigin(rec.Endpoint))
	writeJSON(w, http.StatusOK, pushSubscriptionView(rec))
}

func (s *Server) pushSubscriptionsGet(w http.ResponseWriter, r *http.Request) {
	list := s.push.list()
	out := make([]map[string]interface{}, 0, len(list))
	for _, rec := range list {
		out = append(out, pushSubscriptionView(rec))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"object": "list", "data": out})
}

func (s *Server) pushSubscriptionDelete(w http.ResponseWriter, r *http.Request) {
	if !s.push.unsubscribe(strings.TrimSpace(r.PathValue("id"))) {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "no such subscription"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pushTestPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Device string `json:"device"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, maxPushBodyBytes)).Decode(&body)
	sent, err := s.push.sendTest(r.Context(), strings.TrimSpace(body.Device))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sent": sent})
}

// pushReceiptPost records that a service worker received a push: the delay
// between the server's hand-over and the device's receipt is the delivery
// time a person waits for.
func (s *Server) pushReceiptPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tag        string `json:"tag"`
		Kind       string `json:"kind"`
		Device     string `json:"device"`
		SentAt     int64  `json:"sentAt"`
		ReceivedAt int64  `json:"receivedAt"`
		Action     string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPushBodyBytes)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}
	attrs := []interface{}{"kind", limitText(body.Kind, 32), "device", limitText(body.Device, 64)}
	if body.SentAt > 0 && body.ReceivedAt > 0 {
		attrs = append(attrs, "delivery_ms", body.ReceivedAt-body.SentAt)
	}
	if a := limitText(body.Action, 16); a != "" {
		attrs = append(attrs, "action", a, "action_after_send_ms", time.Now().UnixMilli()-body.SentAt)
	}
	s.log.Info("push received", attrs...)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) presencePost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Device    string `json:"device"`
		Attentive bool   `json:"attentive"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPushBodyBytes)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}
	device := limitText(body.Device, 64)
	if device == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "device is required"})
		return
	}
	s.push.setPresence(device, s.requestPrincipal(r), body.Attentive)
	w.WriteHeader(http.StatusNoContent)
}

func pushSubscriptionView(rec pushSubscriptionRecord) map[string]interface{} {
	v := map[string]interface{}{
		"id":        rec.ID,
		"device":    rec.Device,
		"lang":      rec.Lang,
		"origin":    endpointOrigin(rec.Endpoint),
		"createdAt": rec.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !rec.LastSuccessAt.IsZero() {
		v["lastSuccessAt"] = rec.LastSuccessAt.UTC().Format(time.RFC3339)
	}
	return v
}

// endpointOrigin is what may be shown of an endpoint: its path is the
// capability that lets anyone push to the browser.
func endpointOrigin(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func validPushEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil {
		return "endpoint must be an absolute URL"
	}
	switch u.Scheme {
	case "https":
		return ""
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return ""
		}
	}
	return "endpoint must be https"
}

func validPushKey(v string, size int) bool {
	v = strings.TrimRight(strings.TrimSpace(v), "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(v); err == nil && len(b) == size {
			return true
		}
	}
	return false
}

func limitText(s string, max int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// notifyPush hands one occurrence to the push service with the session's
// title. It never blocks the caller: the title is read on a goroutine of its
// own, as the turn edges are published from the turn's goroutine.
func (s *Server) notifyPush(ev pushAttention) {
	if s == nil || s.push == nil || !s.push.enabled() {
		return
	}
	go func() {
		title := ""
		if s.mgr != nil {
			if st := s.mgr.SessionByID(ev.SessionID); st != nil {
				title = st.ConversationTitle()
			}
		}
		s.push.notify(ev, title)
	}()
}

// pushTurnEdge turns a turn's end into a notice.
func (s *Server) pushTurnEdge(ev session.TurnEvent) {
	if ev.Phase != session.TurnPhaseEnded {
		return
	}
	s.notifyPush(pushAttention{
		Kind:      pushKindTurnFinished,
		SessionID: ev.SessionID,
		Key:       ev.At.UTC().Format(time.RFC3339Nano),
		At:        time.Now(),
	})
}

// pushPermission turns a permission prompt a turn raised into a notice whose
// buttons can answer it.
func (s *Server) pushPermission(params acp.PermissionRequestParams, tool string) {
	allow, reject := "", ""
	for _, o := range params.Options {
		switch {
		case o.Kind == "allow_once" && allow == "":
			allow = o.OptionID
		case o.Kind == "reject_once" && reject == "":
			reject = o.OptionID
		}
	}
	if strings.TrimSpace(tool) == "" {
		tool = strings.TrimSpace(params.ToolCall.Title)
	}
	s.notifyPush(pushAttention{
		Kind:         pushKindPermission,
		SessionID:    strings.TrimSpace(params.SessionID),
		Key:          strings.TrimSpace(params.ToolCall.ToolCallID),
		Detail:       tool,
		ToolCallID:   strings.TrimSpace(params.ToolCall.ToolCallID),
		AllowOption:  allow,
		RejectOption: reject,
		At:           time.Now(),
	})
}

// pushQuestion turns a question the agent asked into a notice.
func (s *Server) pushQuestion(sessionID, key, text string) {
	s.notifyPush(pushAttention{
		Kind:      pushKindQuestion,
		SessionID: strings.TrimSpace(sessionID),
		Key:       strings.TrimSpace(key),
		Detail:    text,
		At:        time.Now(),
	})
}
