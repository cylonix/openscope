// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package output

import (
	"encoding/json"
	"fmt"
	"os"
)

type Response struct {
	OK     bool   `json:"ok"`
	App    string `json:"app,omitempty"`
	Action string `json:"action,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Data   any    `json:"data,omitempty"`
	Error  string `json:"error,omitempty"`
}

func WriteJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func UnmarshalJSON(data []byte, target any) error {
	return json.Unmarshal(data, target)
}

func WriteErrorf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
}
