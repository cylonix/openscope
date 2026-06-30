// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package passport

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// EncodeHandle serializes a Handle to a compact, URL-safe string the issuer
// hands to the external agent (e.g. embedded in the relay connect URL). It
// contains only the public surface — never the Issuer principal or an unsealed
// secret.
func EncodeHandle(h Handle) (string, error) {
	data, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("marshal handle: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeHandle parses a handle string produced by EncodeHandle.
func DecodeHandle(s string) (Handle, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Handle{}, fmt.Errorf("decode handle: %w", err)
	}
	var h Handle
	if err := json.Unmarshal(data, &h); err != nil {
		return Handle{}, fmt.Errorf("unmarshal handle: %w", err)
	}
	return h, nil
}
