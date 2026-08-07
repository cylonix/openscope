// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// maxConfigBlobSize bounds how much of a tar entry we are willing to buffer
// while hunting for the image config JSON. Real config blobs are a few KB;
// layer blobs are orders of magnitude larger and are skipped by this bound, so
// inspection stays O(scan) and never holds a layer in memory.
const maxConfigBlobSize = 4 << 20

// imageConfig is the slice of a docker/OCI image config we care about. The
// config blob is the only place a single-platform `docker save` records what
// the image was built for.
type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// saveManifest is the manifest.json entry list `docker save` writes; Config
// names the config blob inside the tar (either "<digest>.json" or
// "blobs/sha256/<digest>").
type saveManifest []struct {
	Config string `json:"Config"`
}

// dockerImagePlatform reads a `docker save` tar (plain or gzipped — the staged
// artifact is usually gzipped for transfer) and returns the image's platform as
// "os/arch". It prefers the config blob named by manifest.json; when the
// manifest appears after its config in the stream (entry order is not
// guaranteed), it falls back to the first captured blob that parses as an image
// config. Fail closed: an artifact whose platform cannot be determined is an
// error, not a pass.
func dockerImagePlatform(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	var stream io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return "", fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		stream = gz
	}

	tr := tar.NewReader(stream)
	var manifestConfig string            // config blob name per manifest.json, if seen
	captured := map[string]imageConfig{} // candidate config blobs by cleaned name
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read image tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > maxConfigBlobSize {
			continue
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		switch {
		case name == "manifest.json":
			var m saveManifest
			if err := json.NewDecoder(io.LimitReader(tr, maxConfigBlobSize)).Decode(&m); err == nil && len(m) > 0 {
				manifestConfig = path.Clean(strings.TrimPrefix(m[0].Config, "./"))
			}
		case strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "blobs/"):
			data, err := io.ReadAll(io.LimitReader(tr, maxConfigBlobSize))
			if err != nil {
				continue
			}
			var cfg imageConfig
			if json.Unmarshal(data, &cfg) == nil && cfg.Architecture != "" && cfg.OS != "" {
				captured[name] = cfg
			}
		}
		// Both halves known → done; no need to scan the remaining layers.
		if manifestConfig != "" {
			if cfg, ok := captured[manifestConfig]; ok {
				return cfg.OS + "/" + cfg.Architecture, nil
			}
		}
	}

	if manifestConfig != "" {
		if cfg, ok := captured[manifestConfig]; ok {
			return cfg.OS + "/" + cfg.Architecture, nil
		}
	}
	// Manifest missing or its config blob not captured — fall back to any blob
	// that parsed as an image config (a single-platform save has exactly one).
	for _, cfg := range captured {
		return cfg.OS + "/" + cfg.Architecture, nil
	}
	return "", fmt.Errorf("no image config with os/architecture found — is this a `docker save` tar (plain or gzipped)?")
}
