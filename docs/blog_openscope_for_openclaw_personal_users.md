# Lock Down OpenClaw and NemoClaw With OpenScope

If you run OpenClaw on your personal Mac, or NemoClaw inside a local sandbox,
the main security question is simple:

how much raw local power do you want the agent to have?

Many users start by thinking about convenience:

- let the agent read Notes
- let it check Mail
- let it look at Calendar
- let it use more local tools later
- maybe let a sandboxed agent reach back to host resources

That feels reasonable, but the dangerous version of this setup is not obvious at
first. If the agent gets broad local automation access, raw AppleScript, or
future raw credentials, you are not just giving it one useful feature. You are
giving it a general-purpose privileged path into personal data and local apps.

OpenScope is designed to avoid that mistake.

Instead of letting OpenClaw or NemoClaw use raw privileged tools directly,
OpenScope puts a broker in the middle and only exposes a narrow set of approved
actions.

![Filter raw privilege vs expose only scoped access](./diagrams/filter_vs_scope.svg)

## The Core Difference

There are two very different ways to secure an agent:

1. Filter access to a raw privileged tool
2. Do not expose the raw privileged tool at all

OpenScope follows the second approach.

With OpenScope, the agent does not get the raw tool surface in the first place.
It only gets brokered capabilities such as:

- `openscope notes list_notes --folder Work`
- `openscope notes read_note --folder Work --note "Sprint Plan"`
- `openscope mail list_messages --mailbox Inbox`

That changes the security model from:

"watch the privileged path"

to:

"remove the privileged path from the agent."

For a personal user, that is usually the more important property.

## Why This Matters for Personal Users

If you are a personal user, your biggest concern is usually not broad AI
governance. It is:

- can the agent read more than I intended?
- can it wander into private folders?
- can it use some other local path I forgot about?
- can it retain or reuse a credential later?
- if it runs in a sandbox, can it still get broad host powers?

OpenScope helps because it narrows the problem.

OpenClaw uses `openscope`. NemoClaw can also use `openscope` through a
client-only sandbox install. OpenScope evaluates local policy. OpenScope
executes the approved action. The agent never needs raw Apple automation
permission for Notes or Mail.

That is already how the current product is built:

- OpenScope brokers protected access to Apple Notes and Apple Mail
- OpenScope supports scoped actions and parameter-level policy
- OpenScope audits allow and deny decisions
- OpenScope keeps the macOS automation approval on its own signed broker

In plain English: the agent asks, OpenScope decides, and only the approved
narrow operation runs.

## Native OpenClaw and Sandboxed NemoClaw

One of the best parts of the current OpenScope model is that it works for both:

- native OpenClaw on the host Mac
- sandboxed NemoClaw or OpenShell-style environments

For native local use, OpenClaw calls the local `openscope` CLI, which talks to
the host `openscoped` broker.

For a sandboxed setup, you still use `openscope`, but only the client lives in
the sandbox. The protected daemon remains on the host, and the sandbox talks to
it over a provisioned socket or HTTP bridge.

That means the sandbox does not need:

- host shell access
- raw `osascript`
- direct Apple automation permission
- a copy of the host-side privileged broker

For personal users, this is a very clean security shape:

- the host keeps the real broker and policy
- the sandbox gets a client, not the privileged implementation
- your agent workflow stays the same in both environments

## Start With the Built-In Capabilities

For most people, the fastest safe path is to start with the predefined
capabilities OpenScope already ships.

Today those include protected access to:

- Apple Notes
- Apple Mail

And opt-in passthrough access to:

- Calendar
- Reminders
- Contacts
- Safari
- Messages

The important detail is that these are not just generic tool hooks. They are
predefined capabilities with known actions and known policy shapes.

For example, the personal-safe defaults are already opinionated:

- Notes access can be narrowed by folder and note title
- Mail access is read-only and starts scoped to `Inbox`
- sensitive Notes folders can be blocked by protected keywords
- extra passthrough apps remain denied until you explicitly activate them

That is much safer than starting from a blank generic tool surface.

## OpenScope Locks Down the Key Path Too

Another way to think about it is:

where does the privilege live?

![Where the key lives](./diagrams/where_the_key_lives.svg)

With OpenScope, the broker holds the relevant permission and exposes only the
safe action surface.

For local macOS automation, that is especially important. The OpenScope broker
holds the stable automation approval. The agent does not need a direct local
automation route of its own.

That is a much better mental model for a personal device:

- your Mac keeps the sensitive permission in one place
- the agent gets a low-permission label
- policy determines what the label may do
- every decision is logged

## How to Extend OpenScope Safely

If the built-in capabilities are enough, stop there. That is the safest option.

If you need more, extend OpenScope in this order:

1. activate an existing bundled passthrough app only when you need it
2. add narrower policy for the existing app and action surface
3. only then define a new custom app/action manifest

That progression matters because each step keeps more of the trusted capability
design that OpenScope already gives you.

For many personal users, "extend it" should mean:

- add one more allowed Notes folder
- activate Calendar
- narrow Mail to trusted sender domains

not:

- invent a broad raw local automation path

## The Personal Threat Model: Bypass and Overreach

The biggest weakness in broad generic access is coverage.

![Why bypass happens](./diagrams/why_bypass_happens.svg)

If the raw primitive still exists, you always have to worry about:

- another tool path
- another local runtime
- another integration
- a misconfiguration that quietly widens access

OpenScope does not eliminate all risk, but it changes the kind of risk you have.

Instead of worrying mainly about bypass around a broad tool, you worry about
whether the brokered actions and policies are well designed.

That is a better problem to have.

It is easier to reason about:

- `read_note` in `Work`

than:

- "some local automation path that might be able to access Notes in ways I did
  not anticipate"

## A Safe Personal Pattern

For most personal users, a good OpenScope setup looks like this:

- use only the `openclaw` agent label or another dedicated low-permission label
- keep Notes scoped to one or two named folders
- avoid `list_folders` if you do not need discovery
- keep Mail limited to `Inbox`
- use the same OpenScope broker for sandboxed NemoClaw instead of exposing host tools
- do not grant raw local automation or shell access as a shortcut
- activate extra passthrough apps only when there is a real use case

In practice, that usually means commands like:

```bash
openscope notes list_notes --agent openclaw --folder "Work"
openscope notes read_note --agent openclaw --folder "Work" --note "Sprint Plan" --body-only
openscope mail list_messages --agent openclaw --mailbox "Inbox" --limit 20 --unread true
```

This is a much safer pattern than teaching OpenClaw to improvise against local
apps directly.

## The Short Version

OpenScope is a strong fit for personal OpenClaw and NemoClaw hardening because
it does not just filter privileged behavior. It replaces raw privileged
behavior with narrow, brokered actions and gives you useful predefined
capabilities from day one.

That means:

- less raw power exposed to the agent
- less reliance on perfect in-band filtering
- better local containment
- a safer sandboxed-agent story
- a practical default set of protected capabilities
- simpler reasoning about what OpenClaw can and cannot do

For a personal Mac, that is usually the security property that matters most.
