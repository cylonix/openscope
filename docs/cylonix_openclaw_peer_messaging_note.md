# Cylonix OpenClaw Peer Messaging Note

## Context

We explored whether OpenScope should broker messaging for OpenClaw.

Current conclusion:

- OpenScope should not be the default messaging layer for OpenClaw.
- OpenScope remains the scoped local app/action broker.
- OpenClaw human interaction should primarily happen through its channel layer.
- For enterprise, Slack is the likely default channel.
- For personal usage, a first-party Cylonix peer-based channel may be a better fit than Telegram, WhatsApp, or iMessage.

## Why Not iMessage By Default

- Same-Apple-Account iMessage is not a clean agent-to-human channel.
- It creates self-message/sync ambiguity across the user's Mac and phone.
- A separate Apple ID for the agent could work, but it adds setup friction.
- Therefore iMessage should not be a default OpenScope scope for OpenClaw.

## Cylonix Direction

The promising direction is to use Cylonix peer messaging as the personal channel.

High-level product split:

- Cylonix = secure reach / peer transport / phone presence
- OpenClaw = agent + gateway + channel abstraction
- OpenScope = scoped local protected actions when needed

## Current Cylonix Architecture Notes

Relevant observations from the Cylonix repo:

- The Apple Network Extension already hosts peer-facing transport/backend behavior.
- There is existing file/message style bridging via shared app group state and Darwin notifications.
- Tailchat already uses similar patterns for chat/file delivery.
- Cylonix app UI today is primarily a network/control app, not a full chat app.
- File receipt UX is already a good pattern for lightweight peer-originated events.

## Recommended Architecture

### Core recommendation

Use a dedicated OpenClaw peer-messaging lane in Cylonix, separate from Tailchat's normal chat domain.

### Local integration boundary

Preferred boundary:

- OpenClaw integrates through a Tailchat-style or Cylonix-specific channel plugin.
- The plugin should talk to a local proxy/API, not directly to shared app-group files.

### Proxy placement

Two possible designs were discussed:

1. Proxy in Network Extension
- attractive because peer API already lives there
- shortest data path
- but less ideal as a stable plugin-facing integration surface

2. Proxy in Cylonix app or helper daemon
- Network Extension stays responsible for peer transport
- shared app-group queue + Darwin notifications bridge events upward
- app/helper exposes a local WebSocket or similar API to the OpenClaw plugin
- easier lifecycle, auth, buffering, reconnects, metrics, and debugging

Current leaning:

- prefer app/helper as the OpenClaw-facing proxy
- keep Network Extension focused on peer transport/backend duties

## Proposed Message Flow

Recommended flow:

1. Phone peer sends message over Cylonix peer API.
2. Network Extension/backend receives it.
3. Backend classifies it as an OpenClaw-specific event, not a Tailchat chat event.
4. Backend writes event payload into shared app-group storage and posts a Darwin notification.
5. Cylonix app or helper consumes the event.
6. Local OpenClaw channel plugin maintains a WebSocket or similar connection to that local proxy.
7. Proxy pushes inbound events to the plugin.
8. Plugin sends outbound replies back through the same local proxy.
9. Proxy hands outbound messages back down to the peer API/backend.

## Phone UI Direction

Recommendation:

- do not require Tailchat as a separate app for v1
- do not build a full custom chat system from scratch either
- add a lightweight OpenClaw conversation/inbox surface inside Cylonix
- reuse Tailchat UI/code patterns where helpful
- keep OpenClaw messages distinct from Tailchat chat messages

Expected v1 UX:

- simple text thread
- lightweight notification/inbox behavior
- quick replies / approval actions
- attachment support can come later if needed

## OpenClaw Side

Goal:

- avoid modifying OpenClaw core

Likely integration point:

- an OpenClaw channel plugin that connects to the local Cylonix/Tailchat-style proxy

The plugin should not need to observe Darwin notifications directly.
Those should remain an internal Apple-side bridge mechanism.

## Suggested MVP Scope

Start with:

- text in
- text out
- approval prompts
- short task/result summaries

Defer:

- full Tailchat dependency
- attachment-heavy flows
- broad media/chat semantics

## Open Questions

- Should the local OpenClaw-facing proxy live in the Network Extension or in an app/helper process?
- What is the exact local API shape for the OpenClaw plugin: WebSocket, SSE, localhost HTTP, or Unix socket?
- Should the Cylonix phone app expose OpenClaw as a dedicated inbox page, a simple thread page, or a notification-first surface?
- How much Tailchat UI code can be reused without entangling the product concepts?

## Suggested Next Workspace Focus

If we open a new workspace/thread, the next step should probably be in the Cylonix repo, not OpenScope.

Suggested agenda:

1. Inspect the existing peer API and Tailchat bridging implementation in more detail.
2. Decide proxy placement: Network Extension vs app/helper.
3. Define the local plugin-facing API contract.
4. Define the OpenClaw message event schema.
5. Sketch the lightweight phone-side OpenClaw inbox/thread UI.
