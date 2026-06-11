// Package router holds the HTTP handlers for openscope-router.
//
// MVP endpoints:
//
//	POST /v1/scan  — DLP scan of an uploaded file. No upstream call.
//	POST /v1/chat  — DLP + Bedrock forward (Stage 4)
//	GET  /health   — liveness probe
//
// Auth: every request must carry `Authorization: Bearer osk_<role>_<suffix>`.
// pkg/tenancy resolves to a Principal; handlers receive it in context.
package router

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/openscope/openscope/router/internal/dlp"
	"github.com/openscope/openscope/router/internal/store"
	"github.com/openscope/openscope/router/internal/tenancy"
)

// ScanHandler implements POST /v1/scan (Scenario A — block path).
//
// Request:  multipart/form-data with field `file` (UTF-8 text content).
// Response: JSON ScanResponse with decision allow|deny + findings.
type ScanHandler struct {
	Resolver       *tenancy.Resolver
	Scanner        *dlp.Scanner
	Store          RecordStore
	MaxUploadBytes int64
}

type ScanResponse struct {
	RequestID string        `json:"request_id"`
	Decision  string        `json:"decision"`
	Reason    string        `json:"reason,omitempty"`
	Findings  []dlp.Finding `json:"findings,omitempty"`
}

func (h *ScanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// --- Auth -----------------------------------------------------------
	principal, err := h.Resolver.Resolve(ctx, r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing Authorization header")
		return
	}

	// --- Parse multipart upload -----------------------------------------
	r.Body = http.MaxBytesReader(w, r.Body, h.MaxUploadBytes)
	if err := r.ParseMultipartForm(h.MaxUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "could not parse multipart form: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `missing form field "file"`)
		return
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_failed", err.Error())
		return
	}
	text := string(body)
	sum := sha256.Sum256(body)

	// --- DLP scan -------------------------------------------------------
	findings := h.Scanner.Scan(text)

	// --- Decide ---------------------------------------------------------
	requestID := uuid.New()
	decision := "allow"
	result := "success"
	reason := ""
	if len(findings) > 0 {
		decision = "deny"
		result = "dlp_block"
		reason = "matched DLP rule(s): " + strings.Join(dlp.RuleIDs(findings), ", ")
	}

	// --- Persist --------------------------------------------------------
	keyID := principal.KeyID // copy because the store field is *uuid.UUID
	if err := h.Store.AppendRouterEvent(ctx, nil, store.RouterEvent{
		RequestID:  requestID,
		TenantID:   principal.TenantID,
		APIKeyID:   &keyID,
		Role:       principal.Role,
		Endpoint:   "/v1/scan",
		Decision:   decision,
		Result:     result,
		Reason:     reason,
		DLPRuleIDs: dlp.RuleIDs(findings),
		BytesIn:    len(body),
	}); err != nil {
		log.Printf("scan: audit write failed: %v", err)
		writeError(w, http.StatusInternalServerError, "audit_failed", "could not record router event")
		return
	}

	if decision == "deny" {
		findingsJSON, _ := json.Marshal(findings)
		if err := h.Store.InsertUploadedDocument(ctx, nil, store.UploadedDocument{
			RequestID:     requestID,
			TenantID:      principal.TenantID,
			Filename:      header.Filename,
			ContentText:   text,
			ContentSHA256: sum[:],
			DLPFindings:   findingsJSON,
		}); err != nil {
			// Document store failed but the audit row succeeded; log and
			// still return the deny — the customer's record shows what
			// happened even if the body isn't archived.
			log.Printf("scan: uploaded_documents write failed: %v", err)
		}
	}

	// --- Respond --------------------------------------------------------
	writeJSON(w, http.StatusOK, ScanResponse{
		RequestID: requestID.String(),
		Decision:  decision,
		Reason:    reason,
		Findings:  findings,
	})
}

// HealthHandler is a liveness probe — no auth, no DB. Returns 200 always.
// The version field is the update-check seam: deployment tooling and the
// control plane compare it against the latest release manifest.
type HealthHandler struct {
	Version string
}

func (h HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": h.Version})
}

// --- helpers ---------------------------------------------------------------

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorResponse{Code: code, Message: msg})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("write json: %v", err)
	}
}
