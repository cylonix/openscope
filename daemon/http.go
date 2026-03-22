// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/openscope/openscope/ipc"
)

func ListenAndServeHTTP(addr string, service Service) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"service": "openscoped",
		})
	})
	mux.HandleFunc("/v1/actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(ipc.Response{
				OK:       false,
				Error:    "method not allowed",
				ExitCode: ExitInvalid,
			})
			return
		}

		var request ipc.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ipc.Response{
				OK:       false,
				Error:    fmt.Sprintf("decode request: %v", err),
				ExitCode: ExitInvalid,
			})
			return
		}

		response := service.Handle(request)
		w.Header().Set("Content-Type", "application/json")
		if !response.OK {
			w.WriteHeader(httpStatusForExitCode(response.ExitCode))
		}
		_ = json.NewEncoder(w).Encode(response)
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	return server.ListenAndServe()
}

func httpStatusForExitCode(exitCode int) int {
	switch exitCode {
	case ExitOK:
		return http.StatusOK
	case ExitInvalid:
		return http.StatusBadRequest
	case ExitDenied:
		return http.StatusForbidden
	case ExitNotFound:
		return http.StatusNotFound
	case ExitExecutorError:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}
