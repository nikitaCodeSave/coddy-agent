package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// b64 is the encoding of every key and token on the wire: base64url without
// padding.
var b64 = base64.RawURLEncoding

// Keys is the VAPID key pair of the application server (RFC 8292): the P-256
// key that signs every push and whose public half each browser subscribed
// with. A new pair invalidates every subscription made with the old one.
type Keys struct {
	priv *ecdsa.PrivateKey
	pub  []byte // the uncompressed point, 65 bytes
}

// keysFile is the JSON form LoadOrCreateKeys keeps on disk.
type keysFile struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

// GenerateKeys returns a fresh VAPID key pair.
func GenerateKeys() (*Keys, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("webpush: generate VAPID key: %w", err)
	}
	return newKeys(priv)
}

func newKeys(priv *ecdsa.PrivateKey) (*Keys, error) {
	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("webpush: VAPID public key: %w", err)
	}
	return &Keys{priv: priv, pub: pub}, nil
}

// PublicKeyBase64 returns the public key as a browser passes it to
// PushManager.subscribe in applicationServerKey: the uncompressed point in
// base64url without padding.
func (k *Keys) PublicKeyBase64() string { return b64.EncodeToString(k.pub) }

// LoadOrCreateKeys reads the key pair kept at path, or generates one and
// writes it there (mode 0600, the folder created 0700) when the file does not
// exist. A file that exists but does not hold a valid pair is an error and is
// left as it is: replacing it would drop every subscription. The file is
// written through a temporary file and a rename, so a crash never leaves half
// of it; two processes creating it at once are not coordinated.
func LoadOrCreateKeys(path string) (*Keys, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		k, err := parseKeys(data)
		if err != nil {
			return nil, fmt.Errorf("webpush: VAPID keys in %s: %w", path, err)
		}
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("webpush: read VAPID keys: %w", err)
	}
	k, err := GenerateKeys()
	if err != nil {
		return nil, err
	}
	raw, err := k.priv.Bytes()
	if err != nil {
		return nil, fmt.Errorf("webpush: VAPID private key: %w", err)
	}
	data, err = json.MarshalIndent(keysFile{PublicKey: k.PublicKeyBase64(), PrivateKey: b64.EncodeToString(raw)}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("webpush: encode VAPID keys: %w", err)
	}
	if err := writePrivateFile(path, append(data, '\n')); err != nil {
		return nil, fmt.Errorf("webpush: write VAPID keys: %w", err)
	}
	return k, nil
}

func parseKeys(data []byte) (*Keys, error) {
	var f keysFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	raw, err := decodeKey(f.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	k, err := newKeys(priv)
	if err != nil {
		return nil, err
	}
	if pub, err := decodeKey(f.PublicKey); err != nil || !bytes.Equal(pub, k.pub) {
		return nil, errors.New("the public key does not match the private key")
	}
	return k, nil
}

// writePrivateFile writes data to path through a temporary file in the same
// folder, which os.CreateTemp opens with mode 0600, and renames it into place.
func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// decodeKey decodes a key in base64, padded or not, in the URL-safe or the
// standard alphabet: browsers hand over base64url, hand-written clients often
// do not.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return b64.DecodeString(s)
}
