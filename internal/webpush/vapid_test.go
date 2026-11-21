package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

type vapidClaims struct {
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Sub string `json:"sub"`
}

func mustKeys(t *testing.T) *Keys {
	t.Helper()
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifyVAPID parses an Authorization header of RFC 8292, checks the JOSE
// header, verifies the ES256 signature with the key the header names and
// returns the claims and that key.
func verifyVAPID(t *testing.T, header string) (vapidClaims, string) {
	t.Helper()
	rest, ok := strings.CutPrefix(header, "vapid t=")
	if !ok {
		t.Fatalf("Authorization %q does not start with \"vapid t=\"", header)
	}
	token, key, ok := strings.Cut(rest, ", k=")
	if !ok {
		t.Fatalf("Authorization %q has no k=", header)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	var jose map[string]string
	if err := json.Unmarshal(mustB64(t, parts[0]), &jose); err != nil {
		t.Fatal(err)
	}
	if len(jose) != 2 || jose["typ"] != "JWT" || jose["alg"] != "ES256" {
		t.Fatalf("JOSE header = %v, want typ JWT and alg ES256", jose)
	}
	var claims vapidClaims
	dec := json.NewDecoder(bytes.NewReader(mustB64(t, parts[1])))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		t.Fatal(err)
	}
	sig := mustB64(t, parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64 (r || s)", len(sig))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), mustB64(t, key))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the ES256 signature does not verify with the header's key")
	}
	return claims, key
}

func TestAuthorizationHeaderIsASignedVAPIDToken(t *testing.T) {
	k := mustKeys(t)
	now := time.Unix(1_700_000_000, 0)
	header, err := k.AuthorizationHeader("https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV?x=1", "mailto:ops@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, key := verifyVAPID(t, header)
	if key != k.PublicKeyBase64() {
		t.Errorf("k = %s, want %s", key, k.PublicKeyBase64())
	}
	want := vapidClaims{Aud: "https://push.example.net", Exp: now.Add(12 * time.Hour).Unix(), Sub: "mailto:ops@example.com"}
	if claims != want {
		t.Errorf("claims = %+v, want %+v", claims, want)
	}

	// The signature is bound to the key: the same token does not verify with
	// another one.
	other := mustKeys(t)
	token := strings.TrimSuffix(strings.TrimPrefix(header, "vapid t="), ", k="+key)
	parts := strings.Split(token, ".")
	sig := mustB64(t, parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	otherPub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), other.pub)
	if err != nil {
		t.Fatal(err)
	}
	if ecdsa.Verify(otherPub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the signature verifies with an unrelated key")
	}
}

func TestAuthorizationHeaderAudienceIsTheEndpointOrigin(t *testing.T) {
	k := mustKeys(t)
	for _, tc := range []struct{ endpoint, aud string }{
		{"https://fcm.googleapis.com/fcm/send/dGVzdA:APA91b", "https://fcm.googleapis.com"},
		{"https://push.example.net:8443/p/abc?q=1#f", "https://push.example.net:8443"},
		{"HTTPS://Updates.Push.Services.Mozilla.com/wpush/v2/abc", "https://updates.push.services.mozilla.com"},
		{"http://127.0.0.1:9999/push", "http://127.0.0.1:9999"},
		{"http://localhost/push", "http://localhost"},
		{"http://[::1]:8080/push", "http://[::1]:8080"},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			header, err := k.AuthorizationHeader(tc.endpoint, "https://coddy.example.com/contact", time.Unix(0, 0))
			if err != nil {
				t.Fatal(err)
			}
			if claims, _ := verifyVAPID(t, header); claims.Aud != tc.aud {
				t.Fatalf("aud = %q, want %q", claims.Aud, tc.aud)
			}
		})
	}
}

func TestAuthorizationHeaderRejects(t *testing.T) {
	k := mustKeys(t)
	const subject = "mailto:ops@example.com"
	for _, tc := range []struct{ name, endpoint, subject, want string }{
		{"plain http to a remote host", "http://push.example.net/secret-path", subject, "not https"},
		{"another scheme", "ftp://push.example.net/secret-path", subject, "not https"},
		{"no host", "https:///secret-path", subject, "needs a host"},
		{"user info", "https://user:pw@push.example.net/secret-path", subject, "no user info"},
		{"not a URL", "https://push.example.net/secret-path/%zz", subject, "not a URL"},
		{"empty subject", "https://push.example.net/secret-path", "", "subject"},
		{"bare address", "https://push.example.net/secret-path", "ops@example.com", "subject"},
		{"empty mailto", "https://push.example.net/secret-path", "mailto:", "subject"},
		{"mailto with a space", "https://push.example.net/secret-path", "mailto:ops @example.com", "subject"},
		{"http subject", "https://push.example.net/secret-path", "http://example.com", "subject"},
		{"https without a host", "https://push.example.net/secret-path", "https://", "subject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := k.AuthorizationHeader(tc.endpoint, tc.subject, time.Unix(0, 0))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret-path") {
				t.Fatalf("err %q quotes the endpoint's path", err)
			}
		})
	}
}
