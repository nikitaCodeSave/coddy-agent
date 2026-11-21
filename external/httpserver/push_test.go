//go:build http

package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/EvilFreelancer/coddy-agent/internal/webpush"
)

func newTestPushServiceFor(t *testing.T) (*pushService, string) {
	t.Helper()
	home := t.TempDir()
	return newPushService(func() string { return home }, nil), home
}

func testSubscription(t *testing.T, endpoint, device string) pushSubscriptionRecord {
	t.Helper()
	b, err := newTestPushBrowser()
	if err != nil {
		t.Fatal(err)
	}
	return pushSubscriptionRecord{Endpoint: endpoint, P256dh: b.p256dh(), Auth: b.authSecret(), Device: device, Lang: "en"}
}

func TestPushGoneSubscriptionIsRemoved(t *testing.T) {
	gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer gone.Close()
	p, home := newTestPushServiceFor(t)
	if _, err := p.subscribe(testSubscription(t, gone.URL+"/push/x", "phone")); err != nil {
		t.Fatal(err)
	}
	if n, err := p.sendTest(context.Background(), ""); err != nil || n != 0 {
		t.Fatalf("sendTest = %d, %v; want nothing accepted", n, err)
	}
	if n := len(p.list()); n != 0 {
		t.Fatalf("%d subscriptions after a 410, want 0", n)
	}
	raw, _ := os.ReadFile(filepath.Join(home, pushSubscriptionsFile))
	if strings.Contains(string(raw), gone.URL) {
		t.Fatal("the gone subscription is still on disk")
	}
}

func TestPushSkipsASessionNoBrowserPrompted(t *testing.T) {
	p, _ := newTestPushServiceFor(t)
	var got []string
	p.decided = func(kind string, targets int) { got = append(got, kind) }
	p.deliver = func(context.Context, pushSubscriptionRecord, pushNotice) (webpush.Result, error) {
		t.Fatal("a push for a session nobody prompted from a browser")
		return webpush.Result{}, nil
	}
	if _, err := p.subscribe(testSubscription(t, "https://push.example/x", "phone")); err != nil {
		t.Fatal(err)
	}
	// A scheduler run or a Telegram chat: no browser prompted it.
	p.notify(pushAttention{Kind: pushKindTurnFinished, SessionID: "sess_cron", Key: "k"}, "")
	if len(got) != 1 {
		t.Fatalf("decisions %v", got)
	}
}

func TestPushPresenceExpires(t *testing.T) {
	p, _ := newTestPushServiceFor(t)
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	p.setPresence("desk", "local", true)
	p.mu.Lock()
	attended := p.attendedLocked()
	p.mu.Unlock()
	if !attended {
		t.Fatal("a fresh attentive report does not count")
	}
	now = now.Add(pushPresenceTTL + time.Second)
	p.mu.Lock()
	attended = p.attendedLocked()
	p.mu.Unlock()
	if attended {
		t.Fatal("a stale attentive report still silences pushes")
	}
}

func TestPushSubscriptionReplacesTheSameDevicesOldEndpoint(t *testing.T) {
	p, home := newTestPushServiceFor(t)
	if _, err := p.subscribe(testSubscription(t, "https://push.example/old", "phone")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.subscribe(testSubscription(t, "https://push.example/new", "phone")); err != nil {
		t.Fatal(err)
	}
	list := p.list()
	if len(list) != 1 || list[0].Endpoint != "https://push.example/new" {
		t.Fatalf("subscriptions %+v", list)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(home, pushSubscriptionsFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("push-subscriptions.json: %v %v", fi, err)
		}
	}
	again := newPushService(func() string { return home }, nil)
	if n := len(again.list()); n != 1 {
		t.Fatalf("%d subscriptions after a restart", n)
	}
}

func TestValidPushEndpoint(t *testing.T) {
	cases := map[string]bool{
		"https://fcm.googleapis.com/fcm/send/abc": true,
		"https://web.push.apple.com/QH":           true,
		"http://127.0.0.1:9000/push":              true,
		"http://localhost/push":                   true,
		"http://push.example/x":                   false,
		"https://user:pw@push.example/x":          false,
		"/relative":                               false,
		"ftp://push.example/x":                    false,
	}
	for endpoint, ok := range cases {
		if got := validPushEndpoint(endpoint) == ""; got != ok {
			t.Errorf("validPushEndpoint(%q) accepted=%v, want %v", endpoint, got, ok)
		}
	}
}

func TestPushNoticeNeverQuotesMoreThanItsFirstLine(t *testing.T) {
	long := strings.Repeat("x", 400) + "\nsecond line with a secret"
	n := buildPushNotice(pushAttention{Kind: pushKindQuestion, SessionID: "s", Key: "q", Detail: long}, "", "en")
	if strings.Contains(n.Body, "secret") || len([]rune(n.Body)) > 200 {
		t.Fatalf("question body %q", n.Body)
	}
	if n.Title != "Coddy" || n.Tag != "coddy:local:s:question:q" || n.URL != "/#/s/s" {
		t.Fatalf("notice %+v", n)
	}
}

// TestPushMessagesMatchTheSPA holds the server's words to the notify.*
// messages the tabs use, so a push and a tab's notice say the same thing.
func TestPushMessagesMatchTheSPA(t *testing.T) {
	for _, lang := range []string{"en", "ru"} {
		raw, err := os.ReadFile(filepath.Join("..", "ui", "src", "ui", "i18n", "messages", lang+".ts"))
		if err != nil {
			t.Fatal(err)
		}
		msgs := pushMessagesFor(lang)
		for key, want := range map[string]string{
			"notify.untitled":         msgs.untitled,
			"notify.turnFinished":     msgs.turnFinished,
			"notify.permission":       msgs.permission,
			"notify.toolUnnamed":      msgs.toolUnnamed,
			"notify.question":         msgs.question,
			"notify.questionWithText": msgs.questionWithText,
		} {
			re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `":\s*"((?:[^"\\]|\\.)*)"`)
			m := re.FindSubmatch(raw)
			if m == nil {
				t.Fatalf("%s.ts has no %s", lang, key)
			}
			if string(m[1]) != want {
				t.Errorf("%s %s: SPA %q, server %q", lang, key, m[1], want)
			}
		}
	}
}
