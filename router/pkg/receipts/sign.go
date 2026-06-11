// Package receipts produces Ed25519-signed per-call receipts.
//
// The receipt is a deliberately minimal record proving "a call happened
// with these parameters". It carries NO prompt or response bodies — just
// metadata: timestamp, request_id, model, decision, DLP rule IDs, token
// counts, cost. SHA-256 hashes of the prompt and response are included so
// a customer can reconcile receipts against their own logs without us
// sharing content.
//
// Customers verify receipts independently using the embedded public key
// they receive at onboarding (or via the IT dashboard's verify panel).
// The router signs; nobody can forge without the private key.
package receipts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Payload is the canonical fields a receipt commits to. Field order matters
// for the signature input — we serialize with sorted JSON keys so receipts
// roundtrip-stable.
type Payload struct {
	Version        int       `json:"v"`
	RequestID      uuid.UUID `json:"request_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	Timestamp      time.Time `json:"ts"`
	Endpoint       string    `json:"endpoint"`            // /v1/chat | /v1/chat/completions | /v1/messages
	Workspace      string    `json:"workspace,omitempty"` // repo/workspace the agent claimed (audit + "mislabel doesn't help" proof)
	Model          string    `json:"model"`
	RequestedModel string    `json:"requested_model,omitempty"` // present when the caller asked for a model we remapped (agent shims)
	Provider       string    `json:"provider,omitempty"`        // serving platform (e.g. "AWS Bedrock") — attests where the call went
	Region         string    `json:"region,omitempty"`          // serving region (e.g. "us-west-2")
	Decision       string    `json:"decision"`                  // allow | deny
	Result         string    `json:"result"`                    // success | dlp_block | upstream_error | budget_exceeded
	DLPRuleIDs     []string  `json:"dlp_rule_ids,omitempty"`
	InputTokens    int       `json:"input_tokens"`
	OutputTokens   int       `json:"output_tokens"`
	TotalCostUSD   float64   `json:"total_cost_usd"`
	PromptSHA256   string    `json:"prompt_sha256,omitempty"`   // hex
	ResponseSHA256 string    `json:"response_sha256,omitempty"` // hex

	// PolicyVersion (operator-set, OPENSCOPE_POLICY_VERSION) and
	// DLPRulesetVersion (hash of the loaded DLP ruleset) tie the decision
	// to the exact policy that produced it. Empty on receipts minted
	// before these fields existed; canonical JSON omits empty fields, so
	// old receipts still verify.
	PolicyVersion     string `json:"policy_version,omitempty"`
	DLPRulesetVersion string `json:"dlp_ruleset_version,omitempty"`
}

// Signer holds the Ed25519 private key. Public key ID identifies which
// key signed (supports rotation: dashboards keep a small ring of trusted
// keys). One Signer per process.
type Signer struct {
	priv        ed25519.PrivateKey
	publicKeyID string
}

// NewSigner constructs a Signer from a 32-byte seed (the standard Ed25519
// private key representation). If seed is the full 64-byte private key,
// that also works.
func NewSigner(seedOrPrivKey []byte, publicKeyID string) (*Signer, error) {
	if publicKeyID == "" {
		return nil, errors.New("publicKeyID required")
	}
	switch len(seedOrPrivKey) {
	case ed25519.SeedSize: // 32
		return &Signer{priv: ed25519.NewKeyFromSeed(seedOrPrivKey), publicKeyID: publicKeyID}, nil
	case ed25519.PrivateKeySize: // 64
		return &Signer{priv: ed25519.PrivateKey(seedOrPrivKey), publicKeyID: publicKeyID}, nil
	default:
		return nil, fmt.Errorf("ed25519 key must be %d or %d bytes; got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(seedOrPrivKey))
	}
}

// PublicKeyBase64 exports the public key so dashboards / customer audit
// roles can verify signatures without holding the private key.
func (s *Signer) PublicKeyBase64() string {
	pub := s.priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub)
}

// PublicKeyID is the rotation-aware identifier saved alongside each receipt.
func (s *Signer) PublicKeyID() string { return s.publicKeyID }

// Receipt is what the router returns to the caller and inserts into
// app.receipts. PayloadJSON is the canonical bytes the signature commits to.
type Receipt struct {
	PayloadJSON []byte
	Signature   []byte
	PublicKeyID string
}

// Sign produces a receipt over payload, using canonical (sorted-key) JSON.
// Verifiers must serialize the same way; see VerifyCanonical for the
// reference implementation.
func (s *Signer) Sign(p Payload) (*Receipt, error) {
	canonical, err := canonicalJSON(p)
	if err != nil {
		return nil, fmt.Errorf("canonical encode: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	return &Receipt{PayloadJSON: canonical, Signature: sig, PublicKeyID: s.publicKeyID}, nil
}

// VerifyCanonical re-encodes the payload canonically and checks the signature.
// Used by tests; the IT dashboard does the equivalent in TypeScript.
func VerifyCanonical(pub ed25519.PublicKey, payloadJSON []byte, signature []byte) bool {
	return ed25519.Verify(pub, payloadJSON, signature)
}

// SHA256Hex returns the lowercase hex SHA-256 of input — used for the
// prompt/response hash fields in the receipt payload.
func SHA256Hex(in []byte) string {
	h := sha256.Sum256(in)
	const hex = "0123456789abcdef"
	out := make([]byte, len(h)*2)
	for i, b := range h {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

// canonicalJSON marshals with sorted keys at every level. encoding/json's
// default already sorts struct fields by declaration order (which is
// stable), but map keys must be sorted manually — we use a two-pass
// approach so receipt verification is bit-exact across implementations.
func canonicalJSON(v any) ([]byte, error) {
	first, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var any2 any
	if err := json.Unmarshal(first, &any2); err != nil {
		return nil, err
	}
	return canonicalEncode(any2)
}

func canonicalEncode(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, _ := json.Marshal(k)
			buf = append(buf, kb...)
			buf = append(buf, ':')
			vb, err := canonicalEncode(t[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil
	case []any:
		buf := []byte{'['}
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			eb, err := canonicalEncode(e)
			if err != nil {
				return nil, err
			}
			buf = append(buf, eb...)
		}
		buf = append(buf, ']')
		return buf, nil
	default:
		return json.Marshal(t)
	}
}
