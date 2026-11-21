package webpush

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadOrCreateKeysCreatesOnceThenReads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home")
	path := filepath.Join(dir, "webpush.json")

	created, err := LoadOrCreateKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{path: 0o600, dir: 0o700} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Errorf("mode of %s = %o, want %o", p, got, want)
			}
		}
	}
	var f struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if pub := mustB64(t, f.PublicKey); len(pub) != 65 || pub[0] != 0x04 || f.PublicKey != created.PublicKeyBase64() {
		t.Errorf("publicKey %q is not the 65-byte uncompressed point of the pair", f.PublicKey)
	}
	if priv := mustB64(t, f.PrivateKey); len(priv) != 32 {
		t.Errorf("privateKey is %d bytes, want 32", len(priv))
	}

	loaded, err := LoadOrCreateKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicKeyBase64() != created.PublicKeyBase64() {
		t.Fatal("the second call made a new key pair")
	}
	if again, err := os.ReadFile(path); err != nil || !bytes.Equal(again, data) {
		t.Fatalf("the second call rewrote the file (err %v)", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("the folder holds %d entries, want only webpush.json", len(entries))
	}
	// The loaded private key is the created one: its tokens verify with the
	// public key the browsers subscribed with.
	header, err := loaded.AuthorizationHeader("https://push.example.net/p", "mailto:ops@example.com", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, key := verifyVAPID(t, header); key != created.PublicKeyBase64() {
		t.Fatal("the loaded key signs under another public key")
	}
}

func TestLoadOrCreateKeysKeepsABrokenFile(t *testing.T) {
	a, b := mustKeys(t), mustKeys(t)
	bPriv, err := b.priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, content string }{
		{"empty", ""},
		{"not JSON", "not json"},
		{"no keys", "{}"},
		{"short private key", `{"publicKey":"` + a.PublicKeyBase64() + `","privateKey":"AAEC"}`},
		{"keys of two pairs", `{"publicKey":"` + a.PublicKeyBase64() + `","privateKey":"` + b64.EncodeToString(bPriv) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "webpush.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreateKeys(path); err == nil || !strings.HasPrefix(err.Error(), "webpush: ") {
				t.Fatalf("err = %v, want a webpush error", err)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != tc.content {
				t.Fatalf("the broken file was replaced (err %v)", err)
			}
		})
	}
}

func TestDecodeKeyAcceptsEveryBase64Form(t *testing.T) {
	want := []byte{0xfb, 0xff, 0xfe, 0x01}
	for _, s := range []string{"-__-AQ", "-__-AQ==", "+//+AQ", "+//+AQ==", " -__-AQ\n"} {
		got, err := decodeKey(s)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("decodeKey(%q) = %x, %v; want %x", s, got, err, want)
		}
	}
}
