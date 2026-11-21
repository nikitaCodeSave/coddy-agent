//go:build http

package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EvilFreelancer/coddy-agent/internal/webpush"
)

// Web Push for the installed web UI: level two of the notifications
// (docs/plans/pwa-push-notifications.md, phases 2a and 2c, reduced to an MVP).
//
// A tab notifies about what it hears while it is open (level one). This
// service covers the rest: when the agent finishes a turn, asks for a
// permission or asks a question in a chat a browser prompted, and no tab of
// Coddy has anyone's attention, every subscribed browser gets a push through
// the push service its browser vendor runs. The payload is encrypted for the
// browser (RFC 8291), so the push service sees its size and timing only.
//
// MVP simplifications, named so they are not mistaken for the design:
//   - one person: every subscription follows every chat a browser prompted, and
//     an attentive device anywhere silences every push (the plan keys both by
//     principal);
//   - followers live in memory, not in session.json;
//   - a turn's end is "finished": the outcome is not known here yet.

const (
	pushKeysFile          = "webpush.json"
	pushSubscriptionsFile = "push-subscriptions.json"
	// pushSubject is the VAPID contact a push service may use to reach the
	// operator of this server. Apple accepts only mailto: or https:.
	pushSubject = "https://coddy.dev"
	// pushPresenceTTL is how long an attention report counts: a tab repeats it
	// every 60 seconds while it has the person's attention.
	pushPresenceTTL = 90 * time.Second
	// pushTTL is how long a push service keeps an undelivered notice.
	pushTTL = time.Hour
	// pushMaxSubscriptions bounds the store, as a browser can subscribe again
	// with a fresh endpoint whenever it likes.
	pushMaxSubscriptions = 64
)

// Kinds of a notice; the same words the SPA's AttentionKind uses.
const (
	pushKindTurnFinished = "turn_finished"
	pushKindPermission   = "permission"
	pushKindQuestion     = "question"
	pushKindTest         = "test"
)

// pushAttention is one occurrence worth a notice.
type pushAttention struct {
	Kind      string
	SessionID string
	// Key makes the occurrence one: the tool call id, the question id, the
	// turn's end time. The tag a tab builds for the same event carries it.
	Key string
	// Detail is the tool of a permission or the first line of a question.
	Detail string
	// ToolCallID, AllowOption and RejectOption let a notification answer a
	// permission from its buttons.
	ToolCallID   string
	AllowOption  string
	RejectOption string
	At           time.Time
}

// pushNotice is the payload a service worker receives, before encryption.
type pushNotice struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	SessionID string `json:"sessionId,omitempty"`
	Key       string `json:"key,omitempty"`
	Tag       string `json:"tag"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	URL       string `json:"url"`
	Lang      string `json:"lang,omitempty"`
	// SentAt is when the server handed the notice to the push service, in
	// Unix milliseconds: the service worker reports it back with the time it
	// received the push, which is how delivery is measured.
	SentAt     int64  `json:"sentAt"`
	ToolCallID string `json:"toolCallId,omitempty"`
	Allow      string `json:"allow,omitempty"`
	Reject     string `json:"reject,omitempty"`
	// Device is the subscription's device, which the receipt names back.
	Device string `json:"device,omitempty"`
}

// pushSubscriptionRecord is one browser that asked for pushes.
type pushSubscriptionRecord struct {
	ID            string    `json:"id"`
	Endpoint      string    `json:"endpoint"`
	P256dh        string    `json:"p256dh"`
	Auth          string    `json:"auth"`
	Principal     string    `json:"principal,omitempty"`
	Device        string    `json:"device,omitempty"`
	Lang          string    `json:"lang,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	LastSuccessAt time.Time `json:"lastSuccessAt,omitempty"`
}

type pushPresence struct {
	principal string
	attentive bool
	at        time.Time
}

// pushService owns the keys, the subscriptions, the presence table and the
// follower set. It is safe for concurrent use.
type pushService struct {
	home   func() string
	log    *slog.Logger
	client *http.Client
	now    func() time.Time
	// deliver replaces the network send in tests that observe the decision
	// alone; nil sends for real through client.
	deliver func(ctx context.Context, rec pushSubscriptionRecord, notice pushNotice) (webpush.Result, error)
	// decided, when set, hears every decision notify takes: the kind of the
	// occurrence and how many subscriptions it goes to (0 when it is
	// skipped). Tests wait on it instead of on the clock.
	decided func(kind string, targets int)

	mu        sync.Mutex
	keys      *webpush.Keys
	keysHome  string
	subs      map[string]pushSubscriptionRecord
	subsHome  string
	presence  map[string]pushPresence
	followers map[string]time.Time
}

func newPushService(home func() string, log *slog.Logger) *pushService {
	if log == nil {
		log = slog.Default()
	}
	return &pushService{
		home:      home,
		log:       log.With("component", "push"),
		client:    &http.Client{Timeout: 20 * time.Second},
		now:       time.Now,
		presence:  make(map[string]pushPresence),
		followers: make(map[string]time.Time),
	}
}

func (p *pushService) homeDir() string {
	if p == nil || p.home == nil {
		return ""
	}
	return strings.TrimSpace(p.home())
}

// enabled reports whether pushes can be offered: they need an agent home to
// keep the key and the subscriptions in.
func (p *pushService) enabled() bool { return p.homeDir() != "" }

// keysLocked loads or creates the VAPID key pair of the current home.
func (p *pushService) keysLocked() (*webpush.Keys, error) {
	home := p.homeDir()
	if home == "" {
		return nil, fmt.Errorf("push: no agent home")
	}
	if p.keys != nil && p.keysHome == home {
		return p.keys, nil
	}
	k, err := webpush.LoadOrCreateKeys(filepath.Join(home, pushKeysFile))
	if err != nil {
		return nil, err
	}
	p.keys, p.keysHome = k, home
	return k, nil
}

func (p *pushService) publicKey() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k, err := p.keysLocked()
	if err != nil {
		return "", err
	}
	return k.PublicKeyBase64(), nil
}

// subsLocked loads the subscriptions of the current home once.
func (p *pushService) subsLocked() map[string]pushSubscriptionRecord {
	home := p.homeDir()
	if p.subs != nil && p.subsHome == home {
		return p.subs
	}
	p.subs, p.subsHome = make(map[string]pushSubscriptionRecord), home
	if home == "" {
		return p.subs
	}
	data, err := os.ReadFile(filepath.Join(home, pushSubscriptionsFile))
	if err != nil {
		if !os.IsNotExist(err) {
			p.log.Warn("push subscriptions unreadable", "error", err)
		}
		return p.subs
	}
	var file struct {
		Subscriptions []pushSubscriptionRecord `json:"subscriptions"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		p.log.Warn("push subscriptions unreadable", "error", err)
		return p.subs
	}
	for _, rec := range file.Subscriptions {
		if rec.ID != "" && rec.Endpoint != "" {
			p.subs[rec.ID] = rec
		}
	}
	return p.subs
}

func (p *pushService) saveLocked() error {
	home := p.homeDir()
	if home == "" {
		return fmt.Errorf("push: no agent home")
	}
	list := make([]pushSubscriptionRecord, 0, len(p.subs))
	for _, rec := range p.subs {
		list = append(list, rec)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	data, err := json.MarshalIndent(map[string]interface{}{"subscriptions": list}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(filepath.Join(home, pushSubscriptionsFile), data)
}

// writePrivateFileAtomic writes data readable by its owner only, through a
// temporary file in the same folder, so a crash never leaves half a file.
func writePrivateFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// pushSubscriptionID names a subscription by its endpoint, which is what a
// browser hands over again when it subscribes a second time.
func pushSubscriptionID(endpoint string) string {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:8])
}

// subscribe stores or replaces one browser's subscription.
func (p *pushService) subscribe(rec pushSubscriptionRecord) (pushSubscriptionRecord, error) {
	rec.ID = pushSubscriptionID(rec.Endpoint)
	p.mu.Lock()
	defer p.mu.Unlock()
	subs := p.subsLocked()
	if old, ok := subs[rec.ID]; ok {
		rec.CreatedAt, rec.LastSuccessAt = old.CreatedAt, old.LastSuccessAt
	} else {
		rec.CreatedAt = p.now().UTC()
	}
	// One subscription per device: a browser that subscribed again with a new
	// endpoint replaces its old one.
	if rec.Device != "" {
		for id, old := range subs {
			if id != rec.ID && old.Device == rec.Device {
				delete(subs, id)
			}
		}
	}
	if _, ok := subs[rec.ID]; !ok && len(subs) >= pushMaxSubscriptions {
		return pushSubscriptionRecord{}, fmt.Errorf("push: too many subscriptions")
	}
	subs[rec.ID] = rec
	if err := p.saveLocked(); err != nil {
		return pushSubscriptionRecord{}, err
	}
	return rec, nil
}

func (p *pushService) unsubscribe(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	subs := p.subsLocked()
	if _, ok := subs[id]; !ok {
		return false
	}
	delete(subs, id)
	if err := p.saveLocked(); err != nil {
		p.log.Warn("push subscriptions not saved", "error", err)
	}
	return true
}

// dropPrincipal removes every subscription a principal made: a paired device
// that was unpaired takes its pushes with it.
func (p *pushService) dropPrincipal(principal string) {
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	subs := p.subsLocked()
	changed := false
	for id, rec := range subs {
		if rec.Principal == principal {
			delete(subs, id)
			changed = true
		}
	}
	if changed {
		if err := p.saveLocked(); err != nil {
			p.log.Warn("push subscriptions not saved", "error", err)
		}
	}
}

func (p *pushService) list() []pushSubscriptionRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]pushSubscriptionRecord, 0, len(p.subsLocked()))
	for _, rec := range p.subs {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// setPresence records whether a device has the person's attention.
func (p *pushService) setPresence(device, principal string, attentive bool) {
	device = strings.TrimSpace(device)
	if device == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for d, pr := range p.presence {
		if now.Sub(pr.at) > pushPresenceTTL {
			delete(p.presence, d)
		}
	}
	p.presence[device] = pushPresence{principal: principal, attentive: attentive, at: now}
}

// attendedLocked reports whether some device has the person's attention now.
func (p *pushService) attendedLocked() bool {
	now := p.now()
	for _, pr := range p.presence {
		if pr.attentive && now.Sub(pr.at) <= pushPresenceTTL {
			return true
		}
	}
	return false
}

// follow records that a browser prompted the session, which makes its turns
// worth a push.
func (p *pushService) follow(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if p == nil || sessionID == "" {
		return
	}
	p.mu.Lock()
	p.followers[sessionID] = p.now()
	p.mu.Unlock()
}

func (p *pushService) followed(sessionID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.followers[sessionID]
	return ok
}

// notify decides and sends the pushes of one occurrence. It returns at once;
// the sending runs on its own goroutine, so a slow push service never holds a
// turn.
func (p *pushService) notify(ev pushAttention, title string) {
	if p == nil || !p.enabled() || strings.TrimSpace(ev.SessionID) == "" {
		return
	}
	if ev.At.IsZero() {
		ev.At = p.now()
	}
	if !p.followed(ev.SessionID) {
		p.observe(ev.Kind, 0)
		return
	}
	p.mu.Lock()
	attended := p.attendedLocked()
	targets := make([]pushSubscriptionRecord, 0, len(p.subsLocked()))
	for _, rec := range p.subs {
		targets = append(targets, rec)
	}
	p.mu.Unlock()
	if attended {
		p.log.Debug("push skipped: a device has attention", "kind", ev.Kind, "session", ev.SessionID)
		p.observe(ev.Kind, 0)
		return
	}
	p.observe(ev.Kind, len(targets))
	if len(targets) == 0 {
		return
	}
	go p.sendAll(ev, title, targets)
}

func (p *pushService) observe(kind string, targets int) {
	if p.decided != nil {
		p.decided(kind, targets)
	}
}

// sendTest pushes a test notice to the subscriptions of one device, or to
// every subscription when device is empty. It answers how many were accepted.
func (p *pushService) sendTest(ctx context.Context, device string) (int, error) {
	if !p.enabled() {
		return 0, fmt.Errorf("push: no agent home")
	}
	var targets []pushSubscriptionRecord
	for _, rec := range p.list() {
		if device == "" || rec.Device == device {
			targets = append(targets, rec)
		}
	}
	ev := pushAttention{Kind: pushKindTest, Key: fmt.Sprintf("%d", p.now().UnixMilli()), At: p.now()}
	sent := 0
	for _, rec := range targets {
		if p.sendOne(ctx, ev, "", rec) {
			sent++
		}
	}
	return sent, nil
}

func (p *pushService) sendAll(ev pushAttention, title string, targets []pushSubscriptionRecord) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, rec := range targets {
		p.sendOne(ctx, ev, title, rec)
	}
}

// sendOne delivers one notice to one subscription and keeps the store in step
// with the answer: a gone subscription is removed, a success is dated.
func (p *pushService) sendOne(ctx context.Context, ev pushAttention, title string, rec pushSubscriptionRecord) bool {
	notice := buildPushNotice(ev, title, rec.Lang)
	notice.Device = rec.Device
	notice.SentAt = p.now().UnixMilli()
	start := p.now()
	var (
		res webpush.Result
		err error
	)
	phases := &pushPhases{}
	if p.deliver != nil {
		res, err = p.deliver(ctx, rec, notice)
	} else {
		res, err = p.send(httptrace.WithClientTrace(ctx, phases.trace()), rec, notice, ev.Kind)
	}
	took := p.now().Sub(start)
	if err != nil {
		if res.Gone {
			p.mu.Lock()
			delete(p.subsLocked(), rec.ID)
			if serr := p.saveLocked(); serr != nil {
				p.log.Warn("push subscriptions not saved", "error", serr)
			}
			p.mu.Unlock()
			p.log.Info("push subscription gone", "device", rec.Device, "status", res.StatusCode)
			return false
		}
		p.log.Warn("push not delivered", "kind", ev.Kind, "device", rec.Device, "status", res.StatusCode, "error", err)
		return false
	}
	p.mu.Lock()
	if cur, ok := p.subsLocked()[rec.ID]; ok {
		cur.LastSuccessAt = p.now().UTC()
		p.subs[rec.ID] = cur
		if serr := p.saveLocked(); serr != nil {
			p.log.Warn("push subscriptions not saved", "error", serr)
		}
	}
	p.mu.Unlock()
	p.log.Info("push accepted",
		"kind", ev.Kind,
		"session", ev.SessionID,
		"device", rec.Device,
		"status", res.StatusCode,
		"event_to_accept_ms", p.now().Sub(ev.At).Milliseconds(),
		"request_ms", took.Milliseconds(),
		"dns_ms", phases.dns.Milliseconds(),
		"connect_ms", phases.connect.Milliseconds(),
		"tls_ms", phases.tls.Milliseconds(),
		"reused", phases.reused,
	)
	return true
}

// pushPhases measures where the time of one push request goes: a person waits
// for all of it, and the first push to a push service also pays for the lookup
// and the handshakes a pooled connection saves the next one.
type pushPhases struct {
	mu                      sync.Mutex
	dnsAt, connectAt, tlsAt time.Time
	dns, connect, tls       time.Duration
	reused                  bool
}

func (ph *pushPhases) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			ph.mu.Lock()
			ph.reused = info.Reused
			ph.mu.Unlock()
		},
		DNSStart: func(httptrace.DNSStartInfo) { ph.mark(&ph.dnsAt) },
		DNSDone:  func(httptrace.DNSDoneInfo) { ph.since(&ph.dnsAt, &ph.dns) },
		ConnectStart: func(string, string) {
			ph.mark(&ph.connectAt)
		},
		ConnectDone:       func(string, string, error) { ph.since(&ph.connectAt, &ph.connect) },
		TLSHandshakeStart: func() { ph.mark(&ph.tlsAt) },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			ph.since(&ph.tlsAt, &ph.tls)
		},
	}
}

func (ph *pushPhases) mark(at *time.Time) {
	ph.mu.Lock()
	*at = time.Now()
	ph.mu.Unlock()
}

func (ph *pushPhases) since(at *time.Time, d *time.Duration) {
	ph.mu.Lock()
	if !at.IsZero() {
		*d += time.Since(*at)
	}
	ph.mu.Unlock()
}

func (p *pushService) send(ctx context.Context, rec pushSubscriptionRecord, notice pushNotice, kind string) (webpush.Result, error) {
	p.mu.Lock()
	keys, err := p.keysLocked()
	p.mu.Unlock()
	if err != nil {
		return webpush.Result{}, err
	}
	payload, err := json.Marshal(notice)
	if err != nil {
		return webpush.Result{}, err
	}
	urgency := "normal"
	if kind == pushKindPermission || kind == pushKindQuestion {
		urgency = "high"
	}
	sender := &webpush.Sender{Keys: keys, Subject: pushSubject, Client: p.client, Now: p.now}
	return sender.Send(ctx, webpush.Subscription{Endpoint: rec.Endpoint, P256dh: rec.P256dh, Auth: rec.Auth}, payload, webpush.Options{
		TTL:     pushTTL,
		Urgency: urgency,
		Topic:   webpush.TopicFromKey(notice.Tag),
	})
}

// buildPushNotice words the notice in the subscription's language, the way a
// tab words it from the SPA's notify.* messages.
func buildPushNotice(ev pushAttention, title, lang string) pushNotice {
	msgs := pushMessagesFor(lang)
	if strings.TrimSpace(title) == "" {
		title = msgs.untitled
	}
	n := pushNotice{
		V:         1,
		Kind:      ev.Kind,
		SessionID: ev.SessionID,
		Key:       ev.Key,
		Title:     title,
		Lang:      msgs.lang,
		URL:       "/",
	}
	if ev.SessionID != "" {
		n.URL = "/#/s/" + ev.SessionID
		// The tag a tab of the page's own server builds for the same event
		// (noticeTag in src/ui/pwa/notifications.ts), so a push and a tab's
		// notice on one device replace each other.
		n.Tag = "coddy:local:" + ev.SessionID + ":" + ev.Kind + ":" + ev.Key
	} else {
		n.Tag = "coddy:local::" + ev.Kind + ":" + ev.Key
	}
	switch ev.Kind {
	case pushKindTurnFinished:
		n.Body = msgs.turnFinished
	case pushKindPermission:
		tool := strings.TrimSpace(ev.Detail)
		if tool == "" {
			tool = msgs.toolUnnamed
		}
		n.Body = strings.ReplaceAll(msgs.permission, "{tool}", tool)
		n.ToolCallID, n.Allow, n.Reject = ev.ToolCallID, ev.AllowOption, ev.RejectOption
	case pushKindQuestion:
		if q := firstLine(ev.Detail, 140); q != "" {
			n.Body = strings.ReplaceAll(msgs.questionWithText, "{question}", q)
		} else {
			n.Body = msgs.question
		}
	case pushKindTest:
		n.Body = msgs.test
	}
	return n
}

func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}

type pushMessages struct {
	lang             string
	untitled         string
	turnFinished     string
	permission       string
	toolUnnamed      string
	question         string
	questionWithText string
	test             string
}

// pushMessagesFor holds the notify.* messages of the SPA for the languages it
// ships (external/ui/src/ui/i18n/messages); TestPushMessagesMatchTheSPA keeps
// the two in step.
func pushMessagesFor(lang string) pushMessages {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(lang)), "ru") {
		return pushMessages{
			lang:             "ru",
			untitled:         "Coddy",
			turnFinished:     "Агент закончил ход.",
			permission:       "Нужно разрешение: {tool}",
			toolUnnamed:      "инструмент",
			question:         "Агент задал вам вопрос.",
			questionWithText: "Агент спрашивает: {question}",
			test:             "Уведомления работают.",
		}
	}
	return pushMessages{
		lang:             "en",
		untitled:         "Coddy",
		turnFinished:     "The agent finished its turn.",
		permission:       "Permission needed: {tool}",
		toolUnnamed:      "a tool",
		question:         "The agent asked you a question.",
		questionWithText: "The agent asks: {question}",
		test:             "Notifications work.",
	}
}
