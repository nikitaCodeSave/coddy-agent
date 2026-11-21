package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	saltLen       = 16
	authSecretLen = 16
	publicKeyLen  = 65 // an uncompressed P-256 point
	tagLen        = 16
	// recordSize is the rs of the aes128gcm header: the one record of a push
	// message, its padding delimiter and its tag included, fits in it.
	recordSize = 4096
	// headerLen is the aes128gcm header: salt, rs, idlen and the keyid,
	// which is the application server's ephemeral public key.
	headerLen = saltLen + 4 + 1 + publicKeyLen

	// MaxPlaintext is the largest payload one push carries: a push service
	// need not accept a body over 4096 octets (RFC 8030 section 7.2), and the
	// header, the padding delimiter and the GCM tag take 103 of them (RFC 8291
	// section 4).
	MaxPlaintext = 4096 - headerLen - 1 - tagLen
)

// Encrypt encrypts plaintext for one browser with the aes128gcm content
// coding of RFC 8291 and returns the whole request body: the header, with a
// fresh salt and a fresh ephemeral key, then the single record. uaPublic is
// the subscription's p256dh key (an uncompressed P-256 point) and authSecret
// its 16-byte auth secret.
func Encrypt(plaintext, uaPublic, authSecret []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("webpush: salt: %w", err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("webpush: ephemeral key: %w", err)
	}
	return encrypt(plaintext, uaPublic, authSecret, salt, ephemeral)
}

// encrypt is Encrypt with the salt and the ephemeral key given, which is
// what lets a test reproduce the example of RFC 8291 byte for byte.
func encrypt(plaintext, uaPublic, authSecret, salt []byte, ephemeral *ecdh.PrivateKey) ([]byte, error) {
	switch {
	case len(plaintext) > MaxPlaintext:
		return nil, fmt.Errorf("webpush: payload of %d bytes exceeds the %d one push carries", len(plaintext), MaxPlaintext)
	case len(authSecret) != authSecretLen:
		return nil, fmt.Errorf("webpush: auth secret is %d bytes, want %d", len(authSecret), authSecretLen)
	case len(uaPublic) != publicKeyLen:
		return nil, fmt.Errorf("webpush: p256dh key is %d bytes, want %d", len(uaPublic), publicKeyLen)
	case len(salt) != saltLen:
		return nil, fmt.Errorf("webpush: salt is %d bytes, want %d", len(salt), saltLen)
	}
	ua, err := ecdh.P256().NewPublicKey(uaPublic)
	if err != nil {
		return nil, fmt.Errorf("webpush: p256dh key: %w", err)
	}
	shared, err := ephemeral.ECDH(ua)
	if err != nil {
		return nil, fmt.Errorf("webpush: key agreement: %w", err)
	}
	asPublic := ephemeral.PublicKey().Bytes()
	cek, nonce, err := deriveKeys(shared, authSecret, salt, uaPublic, asPublic)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("webpush: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("webpush: cipher: %w", err)
	}
	body := make([]byte, headerLen, headerLen+len(plaintext)+1+tagLen)
	copy(body, salt)
	binary.BigEndian.PutUint32(body[saltLen:], recordSize)
	body[saltLen+4] = publicKeyLen
	copy(body[saltLen+5:], asPublic)
	record := append(append(make([]byte, 0, len(plaintext)+1), plaintext...), 0x02) // the last record's delimiter, no padding
	return gcm.Seal(body, nonce, record, nil), nil
}

// deriveKeys runs the key schedule of RFC 8291 section 3.4: the ECDH secret
// and the auth secret combined into the input keying material, then the
// content encryption key and the nonce of RFC 8188.
func deriveKeys(shared, authSecret, salt, uaPublic, asPublic []byte) (cek, nonce []byte, err error) {
	keyInfo := "WebPush: info\x00" + string(uaPublic) + string(asPublic)
	ikm, err := hkdf.Key(sha256.New, shared, authSecret, keyInfo, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("webpush: derive keys: %w", err)
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("webpush: derive keys: %w", err)
	}
	if cek, err = hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16); err != nil {
		return nil, nil, fmt.Errorf("webpush: derive keys: %w", err)
	}
	if nonce, err = hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12); err != nil {
		return nil, nil, fmt.Errorf("webpush: derive keys: %w", err)
	}
	return cek, nonce, nil
}
