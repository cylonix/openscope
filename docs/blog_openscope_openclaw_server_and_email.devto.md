---
title: Why Not Give OpenClaw Root on the Production Server?
published: false
description: Two everyday jobs, monitoring a production Kubernetes box and summarizing the inbox, run through OpenScope, so a chat-driven agent gets scoped, audited actions instead of a root shell and your mailbox.
tags: ai, security, devops, opensource
cover_image: https://openscopeai.com/blog/cover-openclaw-root-devto-v3.jpg?v=2
canonical_url: https://openscopeai.com/blog/openclaw-root-on-production
---

It is a fair question, and it deserves a real answer instead of a nervous
laugh. OpenClaw is good at real work: check whether a server is healthy,
summarize the morning's email, keep an eye on a production cluster. The fastest
way to let it do all of that is to hand it an SSH key and let it read your Mail.
So why not?

Here is the honest answer. A chat-driven agent with a root shell on production
and an open door to your inbox is not one helpful feature. It is a
general-purpose privileged path, and anyone who can talk to the agent can aim
it. A clever prompt, a poisoned web page it reads, one confused tool call, and
"summarize my inbox" quietly turns into "read everything and run whatever." The
thing to be afraid of was never OpenClaw. It is everything that can reach
OpenClaw.

So the goal is not to trust the agent more. It is to need to trust it less. This
post shows that shape on two everyday jobs:

1. monitor server status of `manage.cylonix.io`
2. summarize the day's unread email

Both run through OpenScope, a capability broker that turns raw privileged access
into scoped, auditable, policy-bound actions. OpenClaw never gets a root shell
and never gets raw access to Mail. It gets a short list of approved actions, and
nothing else.

Everything below is a real run on a real machine. The command output is real,
lightly condensed for readability.

## The shape: broker in the middle

Instead of:

```text
OpenClaw -> ssh root@server         (full root shell)
OpenClaw -> osascript -> Apple Mail (full mailbox access)
```

you use:

```text
OpenClaw -> openscope -> openscoped -> the one approved action
```

OpenScope holds the SSH key and the macOS automation approval. OpenClaw holds a
low-permission label, `openclaw`, and a list of actions that label is allowed
to run. The broker checks policy on every call, runs the approved action, and
writes the decision to an audit log.

That changes the security model from:

"watch the privileged path"

to:

"remove the privileged path from the agent."

## Wiring OpenClaw to OpenScope

OpenScope ships a small MCP server, `openscope-mcp`. It holds no keys and no
policy authority. It is a thin front end that forwards each call to the broker
daemon and exposes only the actions the current agent is allowed to run.

OpenClaw talks to MCP servers through mcporter, so registering OpenScope is one
command:

```bash
mcporter config add openscope \
  --command openscope-mcp --arg --agent --arg openclaw \
  --description "OpenScope capability broker (agent openclaw)" --scope home
```

After that, OpenClaw can see exactly the actions policy allows for the
`openclaw` label, and no more:

```text
$ mcporter list openscope
openscope - OpenScope capability broker (agent openclaw)

  function mail_list_messages(limit?: number, unread?: string);
  function mail_read_message(id: string);
  function ssh_check_host();
  function ssh_host_metrics();
  function ssh_list_dir(path: string);
  function ssh_read_file(path: string);

  ... STDIO openscope-mcp --agent openclaw
```

Two things to notice. The mailbox is pinned to `Inbox` by policy, so it is not
even a parameter the agent can set. And there is no `restart_service`, no
`write_file`, no shell. The tool list is generated live from policy, so it is
also the honest list: if policy changes, the tools change, no restart required.

The CLI form is the documented fallback, and it is what shows up in the audit
log:

```bash
openscope ssh host_metrics --agent openclaw --target cylonix-manage
openscope mail list_messages --agent openclaw --mailbox Inbox --unread true
```

Finally, OpenClaw's workspace manual gets a short contract so the agent knows
the rules: always act as `openclaw`, route these jobs through OpenScope, treat
a denial as final, never fall back to raw `ssh` or `osascript`.

## Job 1: monitor manage.cylonix.io

`manage.cylonix.io` is the Cylonix control plane. It sits behind Cloudflare, so
the broker target points at the origin IP directly rather than the proxy edge.
There is no target for it yet, so the first step is to add one. This is the part
worth slowing down for, because it is where the security actually lives.

### The agent proposes, a human applies

OpenClaw does not grant itself access. It drafts a proposal, a typed YAML file
that says what it wants:

```yaml
ssh_targets:
  add:
    - alias: cylonix-manage
      host: 146.190.157.29            # origin IP; manage.cylonix.io is behind Cloudflare
      user: root
      identity_file: /var/openscope/ssh/cylonix-manage/id_rsa
      allowed_path_prefixes:
        - /var/log
policy:
  add:
    - {effect: allow, agent: openclaw, app: ssh, action: check_host,   constraints: {target: cylonix-manage}}
    - {effect: allow, agent: openclaw, app: ssh, action: host_metrics, constraints: {target: cylonix-manage}}
    - {effect: allow, agent: openclaw, app: ssh, action: list_dir,     constraints: {target: cylonix-manage}}
    - {effect: allow, agent: openclaw, app: ssh, action: read_file,    constraints: {target: cylonix-manage}}
```

Then `openscope plan` reviews it. This step is read-only and needs no sudo. It
renders exactly what the change grants, runs a lint, and checks the proposal
against a root-owned envelope of bounds:

```text
WHAT IT WILL BE ABLE TO DO (from typed fields)
  openclaw | ssh·check_host   | target=cylonix-manage
  openclaw | ssh·host_metrics | target=cylonix-manage
  openclaw | ssh·list_dir     | target=cylonix-manage
  openclaw | ssh·read_file    | target=cylonix-manage

FINDINGS
  HIGH   SSH-ROOT-USER   cylonix-manage   logs in as root
  MEDIUM SSH-BROAD-PREFIX cylonix-manage:/var/log  broad read prefix
  PASS   SSH-NO-BYPASS   ~/.ssh   no ~/.ssh key reaches the new target; verified live
```

That `SSH-NO-BYPASS` line is doing quiet, important work. The plan checks, live,
that none of your personal `~/.ssh` keys can reach the new host. If one could,
the broker boundary would be theater: the agent could just SSH around it. The
key the broker uses is root-owned and unreadable to the agent.

A human applies it, pins the hash, and acknowledges the root-login finding:

```bash
sudo openscope apply --file dist/cylonix-manage.proposal.yaml --expect-hash 2466b42e77e8
```

The target and the rules now live in root-owned files. The same uid the agent
runs as cannot edit them.

### What the agent can now see

The four verbs are read-only and immediately useful. Host identity:

```text
$ openscope ssh check_host --agent openclaw --target cylonix-manage
{ "hostname": "manage-master-1", "os": "Linux", "release": "5.4.0-204-generic",
  "uid": "0", "user": "root" }
```

Node health, parsed into clean fields:

```text
$ openscope ssh host_metrics --agent openclaw --target cylonix-manage
{ "uptime":  "22:40:43 up 449 days, 17:09,  load average: 2.63, 1.78, 1.30",
  "loadavg": "2.63 1.78 1.30",
  "memory":  "Mem: 3919 2458 123 126 1338 1064",
  "disk_root": "/dev/vda1  81106868 67962244 13128240  84% /" }
```

This box is a Kubernetes node, so listing `/var/log/containers` is effectively a
live inventory of the Cylonix stack:

```text
$ openscope ssh list_dir --agent openclaw --target cylonix-manage --path /var/log/containers
cylonix, cylonix-ui, supervisor, log-collector, ipdrawer,
postgres, redis, influxdb, etcd, keycloak, prometheus, traefik,
cilium, coredns, kube-apiserver, kube-scheduler, kube-controller-manager
(33 pod log files)
```

449 days of uptime, moderate load, and a root filesystem at 84 percent. The
agent has enough to write a useful status report, and it got there without a
shell.

### What the agent cannot do

The containment is the point, so it is worth showing the walls.

A verb that is not in the surface is denied at the policy layer:

```text
$ openscope ssh service_status --agent openclaw --target cylonix-manage --service kubelet
no matching allow rule
(exit 3)

$ openscope ssh restart_service --agent openclaw --target cylonix-manage --service kubelet
no matching allow rule
(exit 3)
```

A path outside the allow-list is denied at the target layer, even though
`read_file` itself is allowed. The `/var/log` fence is fail-closed:

```text
$ openscope ssh read_file --agent openclaw --target cylonix-manage --path /etc/passwd
path "/etc/passwd" is not allowed for target "cylonix-manage"
(exit 5)
```

Two independent gates, the policy rule and the target's allow-list, both have to
say yes. The agent reads a node's health and its `/var/log`. It cannot restart a
service, cannot read `/etc`, and cannot reach any other host.

There is one more wall worth showing. Suppose the agent later decides it wants
`service_status` and tries to quietly widen the target's declared services.
OpenScope refuses to mutate a live target in place:

```text
BLOCK  SSH-TARGET-CONFLICT  cylonix-manage
       alias already exists with different settings, apply will refuse
```

Widening an existing target is not a silent edit. It is a fresh, reviewed
change. The agent that drafted the proposal cannot sneak a broader one past the
plan gate.

## Job 2: summarize the day's email

Email is the second job, and it uses the same model with a different app.
OpenScope brokers read-only access to Apple Mail. The `openclaw` label is scoped
to `Inbox`, and an admin-owned sender-domain filter can narrow it further.

```text
$ openscope mail list_messages --agent openclaw --mailbox Inbox --unread true --limit 20
[ { "sender": "The Google Workspace Team", "subject": "[Legal Update] Changes to Terms of Service", "unread": true },
  { "sender": "EZBLOCK INC via TestFlight", "subject": "Cylonix 1.0.12 (13) for iOS is now available to test", "unread": true },
  { "sender": "Microsoft Azure", "subject": "Make sure your Azure payment method is up to date", "unread": true },
  { "sender": "Google Search Console Team", "subject": "Improve Google presence for openscopeai.com", "unread": true },
  ... ]
```

`read_message` returns one message body, again `Inbox`-only. There is no raw
AppleScript anywhere in this path. The macOS automation approval stays on
OpenScope's signed broker, not on the agent, so the agent never holds a general
key to Mail. It asks for one message at a time, and policy decides.

## OpenClaw, doing both jobs for real

Here is the part that ties it together. OpenClaw was given one instruction:
produce a daily ops briefing, server plus email, using OpenScope only. It made
the four calls itself, as the `openclaw` label, and returned this, lightly
condensed for readability:

```text
## Daily Ops Briefing, 2026-06-29

### 1) Server: manage.cylonix.io (cylonix-manage / manage-master-1)
- Health: Up. check_host responding as root on Linux 5.4.
- Uptime: 449 days, ~21h (no recent reboots).
- Load: 2.22 / 1.68 / 1.40 (1/5/15 min), trending up but moderate.
- Memory: 3.9 GB total, ~2.5 GB used, ~1.0 GB available. Tight but OK.
- Disk /: 84% used (67.6 GB of 81 GB; ~13 GB free). Worth watching.
- Cylonix services running (from pod logs):
  - Controller plane: cylonix, cylonix-ui, supervisor, log-collector
  - Data stores: postgres, redis, influxdb, etcd, prometheus, keycloak, ipdrawer
  - Infra: k8s control plane, Cilium + operator, CoreDNS, kube-proxy, Traefik

### 2) Email: 20 unread in Inbox
- Cylonix builds (action): TestFlight iOS 1.0.12 (13) and macOS 1.0.12 (88) ready to test.
- Account/billing (action): Azure "update payment method"; Capital One offer (skippable).
- Search Console: "Improve presence" for openscopeai.com and kidfence.ai.
- Legal/policy (FYI): Google Workspace ToS update.
- Noise: DigitalOcean, NVIDIA, Figma, LinkedIn, Redfin.

Action items:
1. Test new iOS (13) and macOS (88) Cylonix builds.
2. Review billing-program changes.
3. Verify Azure payment method is current.
4. Keep an eye on cylonix-manage disk (84%).

All four OpenScope calls returned cleanly, no policy denials.
```

A genuinely useful briefing: it caught the disk creeping toward full, surfaced
the builds waiting to be tested, and flagged the billing reminder. And every
privileged step underneath it was a scoped, audited OpenScope call.

## The harness, in plain terms

![Filter raw privilege vs expose only scoped access](https://openscopeai.com/blog/filter_vs_scope-v3.png?v=3)

Step back and look at what OpenClaw was actually holding while it did this work:

- a low-permission label, `openclaw`, not a root shell and not a Mail key
- exactly six actions, four read-only server verbs and two read-only mail verbs
- two jobs that are separate principals: the server grants and the mail grants do not overlap
- a per-call policy check, with `deny` overriding `allow`
- an audit record of every decision, allow and deny, in `~/.openscope/audit.jsonl`

And what it was not holding:

- no `ssh` to the host, the broker holds the root-owned key
- no `osascript`, the broker holds the automation approval
- no `restart_service`, no `write_file`, no path outside `/var/log`
- no ability to edit the rules that confine it, those are root-owned

If a prompt ever talks OpenClaw into trying something outside that list, the
result is an `(exit 3)` and a line in the audit log, not an incident. The
interesting question stops being "what could the agent reach if it went wrong,"
and becomes "are these six actions the right six." That is a much better
question to own.

## Try it

OpenScope is open source. The broker, the MCP server, and these app definitions
all live in the public repo.

- Code: https://github.com/cylonix/openscope
- Releases: https://github.com/cylonix/openscope/releases

So go ahead: give OpenClaw a real job on the production server. Just hand it the
actions, not the keys.
