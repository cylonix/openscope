// Package console implements the read API the dashboards consume.
//
// The console runs as a separate binary (cmd/openscope-console) from the
// router (cmd/openscope-router). Same Postgres database; different roles:
//   - tenant_reader  — RLS-scoped, used for developer + IT requests
//   - vendor_reader  — cross-tenant on app schema only; no GRANT on sensitive.*
//   - openscope_admin (admin pool, used by /admin/* for key minting)
//
// Each request picks a pool based on the session's role. Database-side
// GRANTs enforce the privacy boundary: a coding mistake in the console
// that tries to read sensitive.* with vendor_reader fails with
// "permission denied for schema sensitive" — the engine refuses, not us.
package console

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	SessionCookieName = "openscope_session"
	SessionMaxAge     = 8 * time.Hour
)

// Session is what the cookie carries. Minimal — looking up additional info
// (e.g., email, last_used_at) goes through admin queries.
type Session struct {
	TenantID uuid.UUID `json:"t"`
	Role     string    `json:"r"`
	KeyID    uuid.UUID `json:"k"`
	Exp      int64     `json:"e"` // unix seconds
}

// Manager signs and verifies session cookies via HMAC-SHA256.
type Manager struct {
	secret []byte
}

func NewManager(secret []byte) (*Manager, error) {
	if len(secret) < 32 {
		return nil, errors.New("session secret must be at least 32 bytes")
	}
	return &Manager{secret: secret}, nil
}

// Sign returns the cookie value for the given session.
// Format: base64(json) + "." + base64(hmac(secret, json))
func (m *Manager) Sign(s Session) (string, error) {
	if s.Exp == 0 {
		s.Exp = time.Now().Add(SessionMaxAge).Unix()
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify parses the cookie value and checks signature + expiry. Returns the
// session or an error explaining why it's invalid.
func (m *Manager) Verify(cookie string) (Session, error) {
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return Session{}, errors.New("malformed session cookie")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Session{}, errors.New("bad payload encoding")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Session{}, errors.New("bad signature encoding")
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return Session{}, errors.New("bad signature")
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return Session{}, errors.New("bad payload json")
	}
	if time.Now().Unix() >= s.Exp {
		return Session{}, errors.New("session expired")
	}
	return s, nil
}

// SetCookie writes the session cookie to w. HttpOnly + Secure + SameSite=Lax.
// In dev (http://localhost), Secure is set to false so browsers accept the
// cookie; production runs over TLS so this is irrelevant.
func (m *Manager) SetCookie(w http.ResponseWriter, value string, devInsecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !devInsecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionMaxAge.Seconds()),
	})
}

// ClearCookie expires the session cookie (logout).
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// GenerateSecret returns a fresh 32-byte HMAC key, base64-encoded — for
// the deploy bootstrap to populate OPENSCOPE_SESSION_SECRET.
func GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
