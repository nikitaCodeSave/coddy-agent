package webpush

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// vapidLifetime is how long a VAPID token stays valid; RFC 8292 allows at
// most 24 hours.
const vapidLifetime = 12 * time.Hour

// jwtHeader is the encoded JOSE header of every VAPID token.
var jwtHeader = b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))

// AuthorizationHeader returns the Authorization header of RFC 8292 for a push
// to endpoint, "vapid t=<JWT>, k=<public key>": a JWT signed with ES256 whose
// aud is the endpoint's origin, sub the operator's contact (a mailto: or an
// https: URL) and exp twelve hours after now.
func (k *Keys) AuthorizationHeader(endpoint, subject string, now time.Time) (string, error) {
	aud, err := endpointOrigin(endpoint)
	if err != nil {
		return "", err
	}
	if err := checkSubject(subject); err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}{aud, now.Add(vapidLifetime).Unix(), subject})
	if err != nil {
		return "", fmt.Errorf("webpush: VAPID claims: %w", err)
	}
	signingInput := jwtHeader + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("webpush: sign VAPID token: %w", err)
	}
	// JWS carries an ES256 signature as r || s, each 32 bytes (RFC 7518 3.4).
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return "vapid t=" + signingInput + "." + b64.EncodeToString(sig) + ", k=" + k.PublicKeyBase64(), nil
}

// endpointOrigin checks a push endpoint and returns its scheme://host[:port].
// Only https is accepted, and plain http for a loopback host, which is what a
// test against httptest needs. The path of an endpoint is the capability to
// push to one browser, so no error here or in Send quotes it.
func endpointOrigin(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // a url.Error quotes the whole URL
		}
		return "", fmt.Errorf("webpush: endpoint is not a URL: %w", err)
	}
	switch {
	case u.Host == "" || u.User != nil:
		return "", errors.New("webpush: endpoint needs a host and no user info")
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return "", fmt.Errorf("webpush: endpoint scheme %q is not https", u.Scheme)
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

func isLoopback(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}

// checkSubject holds the VAPID sub to what RFC 8292 section 2.1 asks for and
// Apple's push service enforces: a mailto: address or an https: URL.
func checkSubject(sub string) error {
	if addr, ok := strings.CutPrefix(sub, "mailto:"); ok && strings.Contains(addr, "@") && !strings.ContainsAny(addr, " \t\r\n") {
		return nil
	}
	if u, err := url.Parse(sub); err == nil && u.Scheme == "https" && u.Host != "" {
		return nil
	}
	return fmt.Errorf("webpush: VAPID subject %q is neither a mailto: address nor an https: URL", sub)
}
