// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package httpexec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

var placeholderPattern = regexp.MustCompile(`\{([A-Za-z0-9_.-]+)\}`)

type Executor struct {
	Paths  config.Paths
	Client *http.Client
}

func (e Executor) Run(def appdef.Definition, actionName string, params map[string]string) (executor.Result, error) {
	profileName := strings.TrimSpace(params["profile"])
	if profileName == "" {
		return executor.Result{}, fmt.Errorf("profile is required")
	}

	profiles, err := admin.LoadHTTPProfilesOrDefault(e.Paths)
	if err != nil {
		return executor.Result{}, err
	}
	profile, ok := admin.FindHTTPProfile(profiles, profileName)
	if !ok {
		return executor.Result{}, fmt.Errorf("http profile %q not found", profileName)
	}

	action, ok := def.Action(actionName)
	if !ok {
		return executor.Result{}, fmt.Errorf("unknown action %q", actionName)
	}
	method, route, err := parseActionScript(action.Script)
	if err != nil {
		return executor.Result{}, err
	}
	path, err := renderPath(route, params)
	if err != nil {
		return executor.Result{}, err
	}
	requestURL, err := buildURL(profile.BaseURL, path, params)
	if err != nil {
		return executor.Result{}, err
	}
	body, hasBody, err := buildBody(params)
	if err != nil {
		return executor.Result{}, err
	}

	var bodyReader io.Reader
	if hasBody {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, requestURL, bodyReader)
	if err != nil {
		return executor.Result{}, fmt.Errorf("build http request: %w", err)
	}
	for key, value := range profile.Headers {
		req.Header.Set(key, value)
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}

	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: time.Duration(profile.TimeoutSeconds) * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return executor.Result{}, fmt.Errorf("perform http request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return executor.Result{}, fmt.Errorf("read http response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(responseBody))
		if message == "" {
			message = resp.Status
		}
		return executor.Result{}, fmt.Errorf("http %s %s returned %d: %s", method, path, resp.StatusCode, message)
	}

	payload := map[string]any{
		"profile":     profile.Name,
		"method":      method,
		"path":        path,
		"status":      resp.Status,
		"status_code": resp.StatusCode,
		"data":        decodeBody(responseBody, resp.Header.Get("Content-Type")),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return executor.Result{}, fmt.Errorf("marshal http response: %w", err)
	}
	return executor.Result{Stdout: string(data), ExitCode: 0}, nil
}

func parseActionScript(script string) (string, string, error) {
	parts := strings.Fields(strings.TrimSpace(script))
	if len(parts) < 2 {
		return "", "", fmt.Errorf("http action script must be \"METHOD /path\"")
	}
	method := strings.ToUpper(parts[0])
	route := parts[1]
	if !strings.HasPrefix(route, "/") {
		return "", "", fmt.Errorf("http action route must start with /")
	}
	return method, route, nil
}

func renderPath(route string, params map[string]string) (string, error) {
	missing := []string{}
	rendered := placeholderPattern.ReplaceAllStringFunc(route, func(match string) string {
		name := placeholderPattern.FindStringSubmatch(match)[1]
		value := strings.TrimSpace(params[name])
		if value == "" {
			missing = append(missing, name)
			return match
		}
		return url.PathEscape(value)
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("missing path parameters: %s", strings.Join(missing, ", "))
	}
	return rendered, nil
}

func buildURL(baseURL, path string, params map[string]string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("parse path: %w", err)
	}
	resolved := base.ResolveReference(rel)
	query := resolved.Query()
	for key, value := range params {
		if !strings.HasPrefix(key, "query.") {
			continue
		}
		name := strings.TrimPrefix(key, "query.")
		if strings.TrimSpace(name) == "" {
			continue
		}
		query.Set(name, value)
	}
	resolved.RawQuery = query.Encode()
	return resolved.String(), nil
}

func buildBody(params map[string]string) ([]byte, bool, error) {
	body := map[string]string{}
	for key, value := range params {
		if !strings.HasPrefix(key, "body.") {
			continue
		}
		name := strings.TrimPrefix(key, "body.")
		if strings.TrimSpace(name) == "" {
			continue
		}
		body[name] = value
	}
	if len(body) == 0 {
		return nil, false, nil
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, false, fmt.Errorf("marshal request body: %w", err)
	}
	return data, true, nil
}

func decodeBody(body []byte, contentType string) any {
	if strings.Contains(strings.ToLower(contentType), "json") {
		var decoded any
		if err := json.Unmarshal(body, &decoded); err == nil {
			return decoded
		}
	}
	return strings.TrimSpace(string(body))
}
