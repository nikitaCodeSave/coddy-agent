package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The example of RFC 8291, section 5 and Appendix A
// (https://www.rfc-editor.org/rfc/rfc8291.txt), copied verbatim with the line
// breaks and the whitespace the RFC puts inside its values removed. The
// example's Content-Length line says 145, while its own body is 144 octets:
// the 86-octet header and 58 octets of ciphertext.
const (
	rfcPlaintext  = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"
	rfcASPublic   = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	rfcASPrivate  = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcUAPublic   = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcUAPrivate  = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	rfcSalt       = "DGv6ra1nlYgDCS1FRnbzlw"
	rfcAuthSecret = "BTBZMqHH6r4Tts7J_aSIgg"
	rfcECDHSecret = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs"
	rfcCEK        = "oIhVW04MRdy2XN9CiKLxTg"
	rfcNonce      = "4h_95klXJ5E_qnoN"
	rfcHeader     = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	rfcCiphertext = "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ"
	rfcBody       = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func TestEncryptReproducesRFC8291Example(t *testing.T) {
	ephemeral, err := ecdh.P256().NewPrivateKey(mustB64(t, rfcASPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ephemeral.PublicKey().Bytes(), mustB64(t, rfcASPublic)) {
		t.Fatal("the RFC's as_private does not give its as_public")
	}
	got, err := encrypt(mustB64(t, rfcPlaintext), mustB64(t, rfcUAPublic), mustB64(t, rfcAuthSecret), mustB64(t, rfcSalt), ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:headerLen], mustB64(t, rfcHeader)) {
		t.Errorf("header\n got %s\nwant %s", b64.EncodeToString(got[:headerLen]), rfcHeader)
	}
	if !bytes.Equal(got[headerLen:], mustB64(t, rfcCiphertext)) {
		t.Errorf("ciphertext\n got %s\nwant %s", b64.EncodeToString(got[headerLen:]), rfcCiphertext)
	}
	if !bytes.Equal(got, mustB64(t, rfcBody)) {
		t.Errorf("body\n got %s\nwant %s", b64.EncodeToString(got), rfcBody)
	}
}

func TestDeriveKeysMatchesRFC8291IntermediateValues(t *testing.T) {
	ua, err := ecdh.P256().NewPrivateKey(mustB64(t, rfcUAPrivate))
	if err != nil {
		t.Fatal(err)
	}
	as, err := ecdh.P256().NewPublicKey(mustB64(t, rfcASPublic))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ua.ECDH(as)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, mustB64(t, rfcECDHSecret)) {
		t.Fatalf("ecdh_secret = %s, want %s", b64.EncodeToString(shared), rfcECDHSecret)
	}
	cek, nonce, err := deriveKeys(shared, mustB64(t, rfcAuthSecret), mustB64(t, rfcSalt), mustB64(t, rfcUAPublic), mustB64(t, rfcASPublic))
	if err != nil {
		t.Fatal(err)
	}
	if got := b64.EncodeToString(cek); got != rfcCEK {
		t.Errorf("CEK = %s, want %s", got, rfcCEK)
	}
	if got := b64.EncodeToString(nonce); got != rfcNonce {
		t.Errorf("NONCE = %s, want %s", got, rfcNonce)
	}
}

// browser is the receiving side of RFC 8291 as a user agent runs it, written
// apart from the package's code so that a round trip checks one against the
// other. TestBrowserDecryptsRFC8291Example holds it to the RFC first.
type browser struct {
	key  *ecdh.PrivateKey
	auth []byte
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	return &browser{key: key, auth: auth}
}

// subscription is what PushSubscription.toJSON() hands over: base64url
// without padding.
func (b *browser) subscription(endpoint string) Subscription {
	return Subscription{
		Endpoint: endpoint,
		P256dh:   base64.RawURLEncoding.EncodeToString(b.key.PublicKey().Bytes()),
		Auth:     base64.RawURLEncoding.EncodeToString(b.auth),
	}
}

func (b *browser) decrypt(body []byte) ([]byte, error) {
	if len(body) < 21 {
		return nil, errors.New("body shorter than a header")
	}
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	if len(body) < 21+idlen {
		return nil, errors.New("body shorter than its keyid")
	}
	as, err := ecdh.P256().NewPublicKey(body[21 : 21+idlen])
	if err != nil {
		return nil, fmt.Errorf("keyid: %w", err)
	}
	record := body[21+idlen:]
	if uint32(len(record)) > rs {
		return nil, fmt.Errorf("record of %d bytes over rs %d", len(record), rs)
	}
	shared, err := b.key.ECDH(as)
	if err != nil {
		return nil, err
	}
	keyInfo := "WebPush: info\x00" + string(b.key.PublicKey().Bytes()) + string(as.Bytes())
	ikm, err := hkdf.Key(sha256.New, shared, b.auth, keyInfo, 32)
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
	plain, err := gcm.Open(nil, nonce, record, nil)
	if err != nil {
		return nil, err
	}
	// Padding is zeros after the delimiter; the last record's is 0x02.
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 || plain[i] != 0x02 {
		return nil, errors.New("no last-record delimiter")
	}
	return plain[:i], nil
}

func TestBrowserDecryptsRFC8291Example(t *testing.T) {
	key, err := ecdh.P256().NewPrivateKey(mustB64(t, rfcUAPrivate))
	if err != nil {
		t.Fatal(err)
	}
	b := &browser{key: key, auth: mustB64(t, rfcAuthSecret)}
	got, err := b.decrypt(mustB64(t, rfcBody))
	if err != nil {
		t.Fatal(err)
	}
	if want := "When I grow up, I want to be a watermelon"; string(got) != want {
		t.Fatalf("plaintext = %q, want %q", got, want)
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	b := newBrowser(t)
	uaPublic := b.key.PublicKey().Bytes()
	for _, plaintext := range [][]byte{
		{},
		[]byte("x"),
		[]byte(`{"v":1,"kind":"permission","sessionId":"sess_1","title":"Coddy"}`),
		bytes.Repeat([]byte{0}, 64), // trailing zeros must survive the padding strip
		bytes.Repeat([]byte("a"), MaxPlaintext),
	} {
		t.Run(fmt.Sprintf("%d bytes", len(plaintext)), func(t *testing.T) {
			body, err := Encrypt(plaintext, uaPublic, b.auth)
			if err != nil {
				t.Fatal(err)
			}
			if want := headerLen + len(plaintext) + 1 + tagLen; len(body) != want || len(body) > 4096 {
				t.Fatalf("body is %d bytes, want %d and at most 4096", len(body), want)
			}
			got, err := b.decrypt(body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("decrypted %q, want %q", got, plaintext)
			}
			again, err := Encrypt(plaintext, uaPublic, b.auth)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(again[:headerLen], body[:headerLen]) {
				t.Fatal("two messages share a salt and an ephemeral key")
			}
		})
	}
}

func TestEncryptRejectsBadInput(t *testing.T) {
	b := newBrowser(t)
	uaPublic := b.key.PublicKey().Bytes()
	offCurve := make([]byte, 65) // (1, 1) is not on P-256
	offCurve[0], offCurve[32], offCurve[64] = 0x04, 1, 1
	compressed := append([]byte{0x02 | uaPublic[64]&1}, uaPublic[1:33]...)
	wrongPrefix := append([]byte{0x05}, uaPublic[1:]...)

	for _, tc := range []struct {
		name            string
		plaintext, ua   []byte
		auth            []byte
		wantErrContains string
	}{
		{"payload over one push", make([]byte, MaxPlaintext+1), uaPublic, b.auth, "exceeds"},
		{"short auth secret", nil, uaPublic, b.auth[:15], "auth secret"},
		{"compressed p256dh", nil, compressed, b.auth, "p256dh"},
		{"p256dh off the curve", nil, offCurve, b.auth, "p256dh"},
		{"p256dh with a wrong prefix", nil, wrongPrefix, b.auth, "p256dh"},
		{"no p256dh", nil, nil, b.auth, "p256dh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Encrypt(tc.plaintext, tc.ua, tc.auth)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrContains) || !strings.HasPrefix(err.Error(), "webpush: ") {
				t.Fatalf("err = %v, want a webpush error naming %q", err, tc.wantErrContains)
			}
		})
	}
}
