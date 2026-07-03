// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command openscope-reflect-client is the EXTERNAL (vendor-B) side of the
// cross-org reflector. It turns a passport handle from `openscope share` into a
// working MCP server: it connects to the relay, authenticates the daemon,
// establishes the end-to-end channel, projects the passport's sanctioned verbs
// into MCP tools (the same projection the local openscope-mcp uses), and
// forwards each tool call as an encrypted request to the issuer's daemon.
//
// It holds no policy authority — the daemon runs every call under the issuer's
// attenuated identity and re-checks policy. This binary only orchestrates the
// channel and the tool surface.
package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openscope/openscope/buildinfo"
	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/mcp"
	"github.com/openscope/openscope/passport"
	"github.com/openscope/openscope/reflector"
)

const reflectInstructions = "These tools run scoped debugging verbs on a remote partner's host " +
	"through the OpenScope reflector. They are bound by an ephemeral passport and the issuer's policy; " +
	"a result ending in \"(exit 3)\" is denied and final. The session self-destructs at its TTL."

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		return runKeygen(os.Args[2:])
	}

	fs := flag.NewFlagSet("openscope-reflect-client", flag.ContinueOnError)
	var passportFlag, secretFlag, pinFlag, identityFlag string
	var showVersion bool
	fs.StringVar(&passportFlag, "passport", "", "passport handle from `openscope share`")
	fs.StringVar(&secretFlag, "secret", "", "bearer secret (base64), for --bearer handles only")
	fs.StringVar(&pinFlag, "pin-fingerprint", "", "expected daemon fingerprint (sha256:...), confirmed out of band")
	fs.StringVar(&identityFlag, "identity", defaultIdentityPath(), "recipient identity file (from keygen)")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if showVersion {
		fmt.Println(buildinfo.Version)
		return 0
	}
	if passportFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: openscope-reflect-client --passport <handle> [--secret <b64>] [--pin-fingerprint sha256:...]")
		fmt.Fprintln(os.Stderr, "   or: openscope-reflect-client keygen")
		return 2
	}

	h, err := passport.DecodeHandle(passportFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode passport: %v\n", err)
		return 2
	}
	if err := h.VerifyPin(pinFlag); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}

	var recipientPriv *ecdh.PrivateKey
	if len(h.SealedSecret) > 0 {
		if _, statErr := os.Stat(identityFlag); statErr != nil {
			fmt.Fprintf(os.Stderr, "this passport is sealed to a recipient key, but no identity at %s.\n", identityFlag)
			fmt.Fprintln(os.Stderr, "run `openscope-reflect-client keygen` and have the issuer register the printed key.")
			return 2
		}
		if recipientPriv, err = reflector.LoadOrCreateRecipientIdentity(identityFlag); err != nil {
			fmt.Fprintf(os.Stderr, "load identity: %v\n", err)
			return 2
		}
	}
	var secret []byte
	if secretFlag != "" {
		if secret, err = base64.StdEncoding.DecodeString(secretFlag); err != nil {
			fmt.Fprintf(os.Stderr, "bad --secret: %v\n", err)
			return 2
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	client, err := reflector.Connect(ctx, h, recipientPriv, secret)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "reflector connected (rendezvous %s); serving %d tool(s) over stdio\n", client.Rendezvous(), len(h.Sanctioned))

	proj := mcp.Project(capabilities.Result{Capabilities: h.Sanctioned})
	server := &mcp.Server{
		Conn:         mcp.NewConn(os.Stdin, os.Stdout),
		Provider:     &reflectProvider{proj: proj, client: client},
		Name:         "openscope-reflect",
		Version:      buildinfo.Version,
		Instructions: reflectInstructions,
	}
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp server: %v\n", err)
		return 5
	}
	return 0
}

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	var identityFlag string
	fs.StringVar(&identityFlag, "identity", defaultIdentityPath(), "recipient identity file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	priv, err := reflector.LoadOrCreateRecipientIdentity(identityFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		return 1
	}
	pub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	fmt.Printf("recipient identity stored at %s\n\n", identityFlag)
	fmt.Println("Your reflect public key — send this to the issuer so they can")
	fmt.Println("`openscope contact add <your-alias> <pubkey>`:")
	fmt.Printf("\n  %s\n", pub)
	return 0
}

func defaultIdentityPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".reflect_identity"
	}
	return filepath.Join(home, ".openscope", "reflect_identity")
}

// reflectProvider implements mcp.Provider against the reflector channel. The
// tool surface comes from the passport (projected by the shared mcp.Project), so
// it is structurally incapable of naming a verb outside the sanctioned scope; the
// daemon re-checks policy per call regardless.
type reflectProvider struct {
	proj   mcp.Projection
	client *reflector.ExternalClient
}

func (p *reflectProvider) Tools() []mcp.Tool { return p.proj.Tools }

func (p *reflectProvider) Call(name string, args map[string]json.RawMessage) mcp.ToolResult {
	app, action, params, ok := p.proj.Resolve(name, args)
	if !ok {
		return mcp.TextResult("unknown tool: "+name, true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := p.client.Call(ctx, ipc.Request{App: app, Action: action, Agent: "reflect", Params: params, Mode: "json"})
	if err != nil {
		return mcp.TextResult("reflector call failed: "+err.Error(), true)
	}
	if resp.OK {
		return mcp.TextResult(formatData(resp.Data), false)
	}
	msg := resp.Error
	if msg == "" {
		msg = "request denied"
	}
	return mcp.TextResult(fmt.Sprintf("%s (exit %d)", msg, resp.ExitCode), true)
}

func formatData(data any) string {
	if data == nil {
		return "ok"
	}
	if s, ok := data.(string); ok {
		return s
	}
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("%v", data)
	}
	return string(b)
}
