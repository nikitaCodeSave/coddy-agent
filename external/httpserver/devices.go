//go:build http

package httpserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Devices paired by a QR code: a phone that scanned the code the web UI shows
// on the computer gets a credential of its own, with no password typed and no
// certificate installed. It is the way into a server that is reached under
// another name than localhost (a LAN address behind a TLS proxy, a tailnet
// name, a tunnel): such a request is refused today unless the server has a
// credential, and a paired device's cookie is one.
//
// A pairing code lives pairingCodeTTL and opens at most pairingCodeUses
// browsers: on iPhone the app added to the home screen keeps cookies apart from
// Safari, so the person who scanned the code in Safari opens the app and uses
// the same code there. The device's token is kept as a SHA-256 digest only, in
// <home>/devices.json, so a paired phone survives a restart of the server.

const (
	devicesFile            = "devices.json"
	deviceCookieBaseName   = "coddy_device"
	pairingCodeTTL         = 10 * time.Minute
	pairingCodeUses        = 2
	pairingMaxOutstanding  = 8
	pairingMaxFailures     = 20
	deviceIdleTTL          = 90 * 24 * time.Hour
	deviceCookieMaxAge     = 400 * 24 * time.Hour
	deviceSeenWriteEvery   = time.Hour
	maxDevices             = 32
	pairingCodeAlphabetLen = 8
)

// pairingAlphabet leaves out the letters a person confuses when typing a code
// off a screen (0/O, 1/I/L).
var pairingEncoding = base32.NewEncoding("ABCDEFGHJKMNPQRSTUVWXYZ23456789!").WithPadding(base32.NoPadding)

type deviceRecord struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	TokenHash  string    `json:"tokenHash"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

type pairingCode struct {
	expiresAt time.Time
	uses      int
}

type deviceStore struct {
	home func() string
	log  *slog.Logger
	now  func() time.Time

	mu       sync.Mutex
	loaded   string
	devices  map[string]deviceRecord // by id
	byHash   map[string]string       // token hash -> id
	codes    map[string]*pairingCode // by normalized code
	failures int
}

func newDeviceStore(home func() string, log *slog.Logger) *deviceStore {
	if log == nil {
		log = slog.Default()
	}
	return &deviceStore{
		home:  home,
		log:   log.With("component", "devices"),
		now:   time.Now,
		codes: make(map[string]*pairingCode),
	}
}

func (d *deviceStore) homeDir() string {
	if d == nil || d.home == nil {
		return ""
	}
	return strings.TrimSpace(d.home())
}

func (d *deviceStore) loadLocked() {
	home := d.homeDir()
	if d.devices != nil && d.loaded == home {
		return
	}
	d.devices, d.byHash, d.loaded = make(map[string]deviceRecord), make(map[string]string), home
	if home == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(home, devicesFile))
	if err != nil {
		if !os.IsNotExist(err) {
			d.log.Warn("paired devices unreadable", "error", err)
		}
		return
	}
	var file struct {
		Devices []deviceRecord `json:"devices"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		d.log.Warn("paired devices unreadable", "error", err)
		return
	}
	for _, rec := range file.Devices {
		if rec.ID != "" && rec.TokenHash != "" {
			d.devices[rec.ID] = rec
			d.byHash[rec.TokenHash] = rec.ID
		}
	}
}

func (d *deviceStore) saveLocked() error {
	home := d.homeDir()
	if home == "" {
		return fmt.Errorf("devices: no agent home")
	}
	list := d.listLocked()
	data, err := json.MarshalIndent(map[string]interface{}{"devices": list}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(filepath.Join(home, devicesFile), data)
}

func (d *deviceStore) listLocked() []deviceRecord {
	list := make([]deviceRecord, 0, len(d.devices))
	for _, rec := range d.devices {
		list = append(list, rec)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	return list
}

func (d *deviceStore) list() []deviceRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	return d.listLocked()
}

// normalizePairingCode accepts the code the way a person types it: any case,
// with or without the dash in the middle.
func normalizePairingCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	return strings.NewReplacer("-", "", " ", "").Replace(code)
}

func displayPairingCode(code string) string {
	if len(code) == pairingCodeAlphabetLen {
		return code[:4] + "-" + code[4:]
	}
	return code
}

// newCode mints a pairing code. The returned value is the code as shown.
func (d *deviceStore) newCode() (string, time.Time, error) {
	if d.homeDir() == "" {
		return "", time.Time{}, fmt.Errorf("devices: no agent home")
	}
	raw := make([]byte, 5) // 40 bits, 8 characters of the alphabet
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	code := pairingEncoding.EncodeToString(raw)[:pairingCodeAlphabetLen]
	if strings.Contains(code, "!") {
		// The 32nd symbol only pads the alphabet; mint again rather than show it.
		return d.newCode()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.sweepCodesLocked(now)
	if len(d.codes) >= pairingMaxOutstanding {
		return "", time.Time{}, fmt.Errorf("devices: too many pairing codes are open")
	}
	exp := now.Add(pairingCodeTTL)
	d.codes[code] = &pairingCode{expiresAt: exp}
	return displayPairingCode(code), exp, nil
}

func (d *deviceStore) sweepCodesLocked(now time.Time) {
	for c, pc := range d.codes {
		if now.After(pc.expiresAt) || pc.uses >= pairingCodeUses {
			delete(d.codes, c)
		}
	}
	if len(d.codes) == 0 {
		d.failures = 0
	}
}

// redeem turns a pairing code into a paired device and its token. A code
// that does not exist counts as a failure; enough failures close every open
// code, so a code cannot be guessed while it is open.
func (d *deviceStore) redeem(code, name string) (deviceRecord, string, error) {
	code = normalizePairingCode(code)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.sweepCodesLocked(now)
	pc, ok := d.codes[code]
	if !ok || code == "" {
		d.failures++
		if d.failures >= pairingMaxFailures {
			d.codes = make(map[string]*pairingCode)
			d.failures = 0
			d.log.Warn("pairing codes closed after repeated wrong codes")
		}
		return deviceRecord{}, "", errPairingCode
	}
	d.loadLocked()
	if len(d.devices) >= maxDevices {
		return deviceRecord{}, "", fmt.Errorf("devices: too many paired devices")
	}
	pc.uses++
	tokenRaw := make([]byte, 32)
	if _, err := rand.Read(tokenRaw); err != nil {
		return deviceRecord{}, "", err
	}
	idRaw := make([]byte, 8)
	if _, err := rand.Read(idRaw); err != nil {
		return deviceRecord{}, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenRaw)
	rec := deviceRecord{
		ID:         hex.EncodeToString(idRaw),
		Name:       limitText(name, 64),
		TokenHash:  deviceTokenHash(token),
		CreatedAt:  now.UTC(),
		LastSeenAt: now.UTC(),
	}
	if rec.Name == "" {
		rec.Name = "Phone"
	}
	d.devices[rec.ID] = rec
	d.byHash[rec.TokenHash] = rec.ID
	if err := d.saveLocked(); err != nil {
		delete(d.devices, rec.ID)
		delete(d.byHash, rec.TokenHash)
		return deviceRecord{}, "", err
	}
	return rec, token, nil
}

var errPairingCode = fmt.Errorf("the pairing code is wrong or has expired")

func deviceTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// lookup answers the device a token belongs to, and keeps it alive: a device
// unused for deviceIdleTTL is forgotten.
func (d *deviceStore) lookup(token string) (deviceRecord, bool) {
	token = strings.TrimSpace(token)
	if d == nil || token == "" {
		return deviceRecord{}, false
	}
	hash := deviceTokenHash(token)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	id, ok := d.byHash[hash]
	if !ok {
		return deviceRecord{}, false
	}
	rec := d.devices[id]
	now := d.now()
	if now.Sub(rec.LastSeenAt) > deviceIdleTTL {
		delete(d.devices, id)
		delete(d.byHash, hash)
		_ = d.saveLocked()
		return deviceRecord{}, false
	}
	if now.Sub(rec.LastSeenAt) > deviceSeenWriteEvery {
		rec.LastSeenAt = now.UTC()
		d.devices[id] = rec
		if err := d.saveLocked(); err != nil {
			d.log.Warn("paired devices not saved", "error", err)
		}
	}
	return rec, true
}

func (d *deviceStore) revoke(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
	rec, ok := d.devices[id]
	if !ok {
		return false
	}
	delete(d.devices, id)
	delete(d.byHash, rec.TokenHash)
	if err := d.saveLocked(); err != nil {
		d.log.Warn("paired devices not saved", "error", err)
	}
	return true
}

// deviceCookieName scopes the cookie to the host the request named, like the
// sign-in form's cookie, so two servers on one host keep their own devices.
func deviceCookieName(r *http.Request) string {
	host := strings.ToLower(strings.TrimSpace(r.Host))
	if host == "" {
		return deviceCookieBaseName
	}
	sum := sha256.Sum256([]byte(host))
	return deviceCookieBaseName + "_" + hex.EncodeToString(sum[:4])
}

// deviceFromRequest answers the paired device whose cookie the request
// carries.
func (s *Server) deviceFromRequest(r *http.Request) (deviceRecord, bool) {
	if s == nil || s.devices == nil || s.noAuth {
		return deviceRecord{}, false
	}
	c, err := r.Cookie(deviceCookieName(r))
	if err != nil || c == nil || c.Value == "" {
		return deviceRecord{}, false
	}
	return s.devices.lookup(c.Value)
}

func (s *Server) registerDeviceRoutes() {
	s.mux.HandleFunc("POST /coddy/devices/pairing", s.devicePairingPost)
	s.mux.HandleFunc("GET /coddy/devices", s.devicesGet)
	s.mux.HandleFunc("DELETE /coddy/devices/{id}", s.deviceDelete)
	s.mux.HandleFunc("POST /coddy/auth/pair", s.coddyAuthPairPost)
}

// devicePairingPost mints a pairing code and the QR code of the address a
// phone opens to use it. The address is the one the body names, else
// httpserver.public_url, else the origin this request came to.
func (s *Server) devicePairingPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseURL string `json:"baseUrl"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, maxPushBodyBytes)).Decode(&body)
	base := strings.TrimSpace(body.BaseURL)
	source := "request"
	if base == "" {
		if c := s.activeCfg(); c != nil && strings.TrimSpace(c.HTTPServer.PublicURL) != "" {
			base, source = strings.TrimSpace(c.HTTPServer.PublicURL), "config"
		}
	} else {
		source = "body"
	}
	if base == "" {
		scheme := "http"
		if requestIsTLS(r) {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "baseUrl must be an http or https address"})
		return
	}
	code, exp, err := s.devices.newCode()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"error": err.Error()})
		return
	}
	link := strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/") + "/#/pair/" + code
	qr, err := enrollmentQR(link)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "could not draw the QR code"})
		return
	}
	s.log.Info("pairing code issued", "base", u.Scheme+"://"+u.Host, "source", source)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":      code,
		"url":       link,
		"qr_png":    qr,
		"expiresAt": exp.UTC().Format(time.RFC3339),
		"secure":    u.Scheme == "https" || isLocalHostName(u.Hostname()),
		"source":    source,
	})
}

func (s *Server) devicesGet(w http.ResponseWriter, r *http.Request) {
	current, _ := s.deviceFromRequest(r)
	list := s.devices.list()
	out := make([]map[string]interface{}, 0, len(list))
	for _, rec := range list {
		out = append(out, map[string]interface{}{
			"id":         rec.ID,
			"name":       rec.Name,
			"createdAt":  rec.CreatedAt.UTC().Format(time.RFC3339),
			"lastSeenAt": rec.LastSeenAt.UTC().Format(time.RFC3339),
			"current":    rec.ID == current.ID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"object": "list", "data": out})
}

func (s *Server) deviceDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if !s.devices.revoke(id) {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "no such device"})
		return
	}
	s.push.dropPrincipal("device:" + id)
	s.log.Info("device unpaired", "device", id)
	w.WriteHeader(http.StatusNoContent)
}

// coddyAuthPairPost redeems a pairing code: the browser that sends it gets
// the device cookie. It is one of the routes the gate lets through, since the
// phone has nothing yet.
func (s *Server) coddyAuthPairPost(w http.ResponseWriter, r *http.Request) {
	if s.noAuth {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "pairing is not offered here"})
		return
	}
	var body struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPushBodyBytes)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}
	if isStateChanging(r) && r.Header.Get("Origin") != "" && !isSameOriginRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": "cross-site request refused"})
		return
	}
	rec, token, err := s.devices.redeem(body.Code, body.Name)
	if err != nil {
		status := http.StatusUnauthorized
		if err != errPairingCode {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]interface{}{"error": err.Error()})
		return
	}
	//nolint:gosec // G124: Secure follows the request's TLS like the sign-in cookie; HttpOnly and SameSite=Strict are set
	cookie := &http.Cookie{ // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
		Name:     deviceCookieName(r),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   requestIsTLS(r),
		MaxAge:   int(deviceCookieMaxAge / time.Second),
	}
	http.SetCookie(w, cookie)
	s.log.Info("device paired", "device", rec.ID, "name", rec.Name, "remote", loginClientAddr(r))
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "device": rec.ID, "name": rec.Name})
}
