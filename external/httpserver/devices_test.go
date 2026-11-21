//go:build http

package httpserver

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newTestDeviceStore(t *testing.T) (*deviceStore, string, *time.Time) {
	t.Helper()
	home := t.TempDir()
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	d := newDeviceStore(func() string { return home }, nil)
	d.now = func() time.Time { return now }
	return d, home, &now
}

func TestPairingCodeOpensTwoBrowsersThenCloses(t *testing.T) {
	d, _, _ := newTestDeviceStore(t)
	code, _, err := d.newCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 9 || code[4] != '-' {
		t.Fatalf("code %q, want XXXX-XXXX", code)
	}
	// Safari, then the app on the home screen, which keeps cookies apart.
	for i := 0; i < pairingCodeUses; i++ {
		if _, _, err := d.redeem(strings.ToLower(strings.ReplaceAll(code, "-", "")), "phone"); err != nil {
			t.Fatalf("use %d: %v", i+1, err)
		}
	}
	if _, _, err := d.redeem(code, "phone"); err != errPairingCode {
		t.Fatalf("third use: %v, want the wrong-code error", err)
	}
	if n := len(d.list()); n != pairingCodeUses {
		t.Fatalf("%d devices, want %d", n, pairingCodeUses)
	}
}

func TestPairingCodeExpires(t *testing.T) {
	d, _, now := newTestDeviceStore(t)
	code, exp, err := d.newCode()
	if err != nil {
		t.Fatal(err)
	}
	if got := exp.Sub(*now); got != pairingCodeTTL {
		t.Fatalf("code lives %v, want %v", got, pairingCodeTTL)
	}
	*now = now.Add(pairingCodeTTL + time.Second)
	if _, _, err := d.redeem(code, "phone"); err != errPairingCode {
		t.Fatalf("expired code: %v, want the wrong-code error", err)
	}
}

func TestWrongPairingCodesCloseEveryOpenCode(t *testing.T) {
	d, _, _ := newTestDeviceStore(t)
	code, _, err := d.newCode()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < pairingMaxFailures; i++ {
		_, _, _ = d.redeem("AAAA-AAAA", "guess")
	}
	if _, _, err := d.redeem(code, "phone"); err != errPairingCode {
		t.Fatalf("the real code after %d wrong ones: %v, want it closed", pairingMaxFailures, err)
	}
}

func TestPairedDeviceSurvivesARestartAndKeepsOnlyADigest(t *testing.T) {
	d, home, now := newTestDeviceStore(t)
	code, _, _ := d.newCode()
	rec, token, err := d.redeem(code, "Pixel")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, devicesFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatal("devices.json carries the token itself")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("devices.json mode %v, want 0600", fi.Mode().Perm())
		}
	}
	again := newDeviceStore(func() string { return home }, nil)
	again.now = func() time.Time { return *now }
	got, ok := again.lookup(token)
	if !ok || got.ID != rec.ID || got.Name != "Pixel" {
		t.Fatalf("after a restart lookup = %+v, %v", got, ok)
	}
	if !again.revoke(rec.ID) {
		t.Fatal("revoke found nothing")
	}
	if _, ok := again.lookup(token); ok {
		t.Fatal("a revoked device still signs in")
	}
}

func TestIdleDeviceIsForgotten(t *testing.T) {
	d, _, now := newTestDeviceStore(t)
	code, _, _ := d.newCode()
	_, token, err := d.redeem(code, "old phone")
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(deviceIdleTTL + time.Hour)
	if _, ok := d.lookup(token); ok {
		t.Fatal("a device unused for longer than the idle limit still signs in")
	}
}

func TestPairingNeedsAnAgentHome(t *testing.T) {
	d := newDeviceStore(func() string { return "" }, nil)
	if _, _, err := d.newCode(); err == nil {
		t.Fatal("a pairing code without a home to keep the device in")
	}
}

func TestUnpairedCookieIsRefusedUnderAnotherName(t *testing.T) {
	st := &mobilePushState{}
	if err := st.openServer("192.168.1.50"); err != nil {
		t.Fatal(err)
	}
	defer st.reset()
	if err := st.computerShowsCode(); err != nil {
		t.Fatal(err)
	}
	if err := st.phonePairs("192.168.1.50"); err != nil {
		t.Fatal(err)
	}
	devices := st.srv.devices.list()
	if len(devices) != 1 {
		t.Fatalf("%d devices", len(devices))
	}
	res, raw, err := st.do(http.MethodDelete, "/coddy/devices/"+devices[0].ID, "", nil)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("unpair: %v %v %s", err, res.Status, raw)
	}
	res, _, err = st.do(http.MethodGet, "/v1/models", "192.168.1.50", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unpaired phone got %s, want 401", res.Status)
	}
	// The page itself and the sign-in routes still answer, so it can pair again.
	res, raw, err = st.do(http.MethodGet, "/coddy/auth/me", "192.168.1.50", nil)
	if err != nil || res.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"pair_required":true`) {
		t.Fatalf("auth/me under another name: %v %v %s", err, res.Status, raw)
	}
}

func TestPairingFromAnotherSiteIsRefused(t *testing.T) {
	st := &mobilePushState{}
	if err := st.openServer("192.168.1.50"); err != nil {
		t.Fatal(err)
	}
	defer st.reset()
	if err := st.computerShowsCode(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, st.ts.URL+"/coddy/auth/pair", strings.NewReader(`{"code":"`+st.code+`"}`))
	req.Host = "192.168.1.50"
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-site pairing got %s, want 403", res.Status)
	}
	if n := len(st.srv.devices.list()); n != 0 {
		t.Fatalf("%d devices paired from another site", n)
	}
}
