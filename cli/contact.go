// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/daemon"
	"github.com/openscope/openscope/output"
)

// contacts.yaml maps a recipient alias to a registered X25519 public key, the
// SSH-authorized_keys / age-recipients pattern. `openscope share --to <alias>`
// resolves the alias here (Tier 1); the key is sealed to so a leaked handle is
// useless to anyone but that recipient.

type contact struct {
	Alias  string `yaml:"alias"`
	Pubkey string `yaml:"pubkey"` // base64 X25519 public key
	Note   string `yaml:"note,omitempty"`
}

type contactsFile struct {
	Version  int       `yaml:"version"`
	Contacts []contact `yaml:"contacts"`
}

func loadContacts(path string) (contactsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return contactsFile{Version: 1}, nil
		}
		return contactsFile{}, err
	}
	var cf contactsFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return contactsFile{}, fmt.Errorf("parse contacts: %w", err)
	}
	if cf.Version == 0 {
		cf.Version = 1
	}
	return cf, nil
}

func saveContacts(path string, cf contactsFile) error {
	cf.Version = 1
	sort.Slice(cf.Contacts, func(i, j int) bool { return cf.Contacts[i].Alias < cf.Contacts[j].Alias })
	data, err := yaml.Marshal(cf)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (cf contactsFile) lookup(alias string) (pubkeyB64 string, ok bool) {
	for _, c := range cf.Contacts {
		if c.Alias == alias {
			return c.Pubkey, true
		}
	}
	return "", false
}

func runContact(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope contact <add|list|remove>")
		return daemon.ExitInvalid
	}
	switch args[0] {
	case "add":
		return runContactAdd(paths, args[1:])
	case "list":
		return runContactList(paths)
	case "remove", "rm":
		return runContactRemove(paths, args[1:])
	default:
		output.WriteErrorf("unknown contact subcommand %q", args[0])
		return daemon.ExitInvalid
	}
}

func runContactAdd(paths config.Paths, args []string) int {
	if len(args) < 2 {
		output.WriteErrorf("usage: openscope contact add <alias> <pubkey-base64> [--note <text>]")
		return daemon.ExitInvalid
	}
	alias, pubkey := args[0], args[1]
	note := ""
	if len(args) >= 4 && args[2] == "--note" {
		note = args[3]
	}
	raw, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil || len(raw) != 32 {
		output.WriteErrorf("pubkey must be a base64-encoded 32-byte X25519 key")
		return daemon.ExitInvalid
	}

	cf, err := loadContacts(paths.ContactsFile)
	if err != nil {
		output.WriteErrorf("load contacts: %v", err)
		return daemon.ExitConfigError
	}
	replaced := false
	for i := range cf.Contacts {
		if cf.Contacts[i].Alias == alias {
			cf.Contacts[i] = contact{Alias: alias, Pubkey: pubkey, Note: note}
			replaced = true
			break
		}
	}
	if !replaced {
		cf.Contacts = append(cf.Contacts, contact{Alias: alias, Pubkey: pubkey, Note: note})
	}
	if err := saveContacts(paths.ContactsFile, cf); err != nil {
		output.WriteErrorf("save contacts: %v", err)
		return daemon.ExitConfigError
	}
	fmt.Printf("contact %q saved\n", alias)
	return daemon.ExitOK
}

func runContactList(paths config.Paths) int {
	cf, err := loadContacts(paths.ContactsFile)
	if err != nil {
		output.WriteErrorf("load contacts: %v", err)
		return daemon.ExitConfigError
	}
	if len(cf.Contacts) == 0 {
		fmt.Println("(no contacts — add one with `openscope contact add <alias> <pubkey>`)")
		return daemon.ExitOK
	}
	for _, c := range cf.Contacts {
		fmt.Printf("%-20s %s", c.Alias, c.Pubkey)
		if c.Note != "" {
			fmt.Printf("  # %s", c.Note)
		}
		fmt.Println()
	}
	return daemon.ExitOK
}

func runContactRemove(paths config.Paths, args []string) int {
	if len(args) < 1 {
		output.WriteErrorf("usage: openscope contact remove <alias>")
		return daemon.ExitInvalid
	}
	alias := args[0]
	cf, err := loadContacts(paths.ContactsFile)
	if err != nil {
		output.WriteErrorf("load contacts: %v", err)
		return daemon.ExitConfigError
	}
	kept := cf.Contacts[:0]
	found := false
	for _, c := range cf.Contacts {
		if c.Alias == alias {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		output.WriteErrorf("no such contact %q", alias)
		return daemon.ExitNotFound
	}
	cf.Contacts = kept
	if err := saveContacts(paths.ContactsFile, cf); err != nil {
		output.WriteErrorf("save contacts: %v", err)
		return daemon.ExitConfigError
	}
	fmt.Printf("contact %q removed\n", alias)
	return daemon.ExitOK
}
