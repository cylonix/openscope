# Cylonix Peer Message Test Guide For OpenScope and NemoClaw

This guide explains how to validate the Cylonix peer message loop from the
local OpenScope repo and a NemoClaw-style local channel client.

The goal is to verify this path end to end:

```text
NemoClaw local channel client
  -> Cylonix app local WebSocket
  -> Cylonix peerMessage LocalAPI
  -> Cylonix peer API transport
  -> remote Cylonix peer
  -> remote Cylonix app inbox/thread UI
```

## Current Cylonix Contract

At the time of writing, the Cylonix app exposes a local WebSocket endpoint while
it is running:

- `ws://127.0.0.1:50321/peer-messaging/v1`

Authentication is required on connect.
The auth token is shown in the Cylonix app under:

- `Peer Messages`

Current implementation note:

- the local API currently accepts an opaque token value and does not validate it yet
- callers may use a placeholder such as `test-token` for early development
- keep passing a token field anyway so the client shape is ready for future validation

The current transport assumptions are:

- the Cylonix app must remain open
- sender and receiver should be on the same user account/tailnet for now
- outbound sends may use either:
  - the target peer's `StableNodeID`
  - the target device FQDN / node name, for example `iphone11.cy123456.cylonix.org`
- the WebSocket `conversation_id` should be set to that peer reference

## What To Prepare

You need:

1. Two devices running the Cylonix build with peer message support
2. Both devices signed into the same Cylonix/Tailscale user for the current peer policy
3. The Cylonix app open on both devices
4. NemoClaw or another local client that can speak JSON over WebSocket

Recommended names in this guide:

- `sender` = the machine where NemoClaw connects to Cylonix
- `receiver` = the machine expected to receive the peer message

## Receiver Setup

On the receiver machine:

1. Launch the Cylonix app
2. Open `Peer Messages`
3. Leave the app running
4. Confirm the inbox page is visible or at least that the app remains open

Expected UI state before the test:

- the local proxy card should say the proxy is running
- the inbox may be empty

## Sender Setup

On the sender machine:

1. Launch the Cylonix app
2. Open `Peer Messages`
3. Copy the following from the proxy card:
   - WebSocket URL
   - auth token
4. Keep the app running

Expected values:

- WebSocket URL: `ws://127.0.0.1:50321/peer-messaging/v1`
- auth token: the value shown in the UI, or a placeholder such as `test-token` during current early development

## Choose The Receiver Peer Reference

For the current implementation, `conversation_id` is also the routing target.

Preferred choice:

- use the receiver device FQDN / node name, for example `iphone11.cy123456.cylonix.org`

Also supported:

- the receiver `StableNodeID`

For early testing, the FQDN is easier for callers than a stable ID.
Do not use a casual display label unless it matches the actual device name in the
current tailnet netmap.

## WebSocket Handshake

The client must connect and immediately authenticate.

Authentication frame:

```json
{
  "type": "authenticate",
  "payload": {
    "token": "<peer-messaging-auth-token>"
  }
}
```

Expected server responses:

1. `authenticated`
2. `sync_snapshot`

Example response shapes:

```json
{
  "version": "v1",
  "type": "authenticated",
  "conversation_id": "",
  "timestamp": "2026-03-23T00:00:00Z",
  "payload": {
    "url": "ws://127.0.0.1:50321/peer-messaging/v1"
  }
}
```

```json
{
  "version": "v1",
  "type": "sync_snapshot",
  "conversation_id": "",
  "timestamp": "2026-03-23T00:00:00Z",
  "payload": {
    "state": {
      "initialized": true,
      "conversations": [],
      "proxy": {
        "is_running": true,
        "url": "ws://127.0.0.1:50321/peer-messaging/v1",
        "auth_token": "..."
      }
    }
  }
}
```

## Send A Text Message

After authentication, send a `send_message` frame.

Use the receiver peer reference for both:

- `conversation_id`
- the effective routing target inside Cylonix

Example:

```json
{
  "type": "send_message",
  "payload": {
    "conversation_id": "iphone11.cy123456.cylonix.org",
    "conversation_title": "Receiver Mac",
    "text": "hello from NemoClaw via Cylonix peerMessage"
  }
}
```

## Expected Results

### On the sender WebSocket

You should see:

- `message_sent`

### On the sender Cylonix UI

You should see:

- a thread created or updated for that conversation
- the outbound message visible in the thread

### On the receiver Cylonix UI

You should see:

- a new conversation appear in `Peer Messages`
- unread count increment
- the incoming message visible in the thread

If notifications are enabled on Apple, you may also see a local user
notification for the inbound message.

## Suggested NemoClaw Test Procedure

Inside NemoClaw, implement the smallest possible local channel client:

1. connect to the local Cylonix WebSocket
2. authenticate with the token from the Cylonix UI
   - for current local testing, a placeholder token such as `test-token` also works
3. wait for `authenticated`
4. wait for `sync_snapshot`
5. send one `send_message` frame to the receiver peer reference
6. log every received server frame

For the first pass, keep the client dumb:

- no reconnect logic required
- no buffering required
- just print frames and exit after one send if desired

## Minimal Success Criteria

Treat the path as validated when all of these are true:

1. NemoClaw connects successfully to the local Cylonix WebSocket
2. authentication succeeds
3. `message_sent` is observed on the sender side
4. the receiver Cylonix app shows the inbound message
5. the sender and receiver thread contents match

## Optional Approval Test

Cylonix also supports approval-style responses in the local API.
If NemoClaw wants to validate that path too, it can send or respond to approval
messages using:

- `submit_approval`

That is a secondary test.
Start with plain text first.

## Failure Modes And What They Usually Mean

### Connection refused

Usually means:

- the Cylonix app is not open
- the local proxy failed to start

Check the `Peer Messages` screen in the sender app.
The proxy card should say it is running.

### Authentication failed

Usually means:

- wrong token
- stale token copied from an older app state

Once Cylonix starts validating tokens, copy the token again from the sender app UI.

### Immediate send failure

Usually means:

- invalid receiver stable ID
- receiver peer not reachable in the current netmap

Verify the exact stable ID.

### Sender sees local thread update but receiver gets nothing

Usually means:

- wrong receiver stable ID
- receiver not online
- receiver not permitted by current same-user peer policy
- remote app not actually on a compatible build

### Receiver gets nothing when the app is closed

This is expected for v1.
The current design requires the Cylonix app to be open for the local plugin
bridge and app-side inbox behavior.

## Recommended Logging During Early Validation

On the NemoClaw side, log:

- WebSocket connect start
- authenticate frame sent
- every frame received
- exact peer reference used in `conversation_id`
- final send result

On the Cylonix side, it helps to capture:

- sender app Peer Messages UI state
- receiver app Peer Messages UI state
- any transport or local proxy logs if available

## Current Protocol Summary

Endpoint:

- `ws://127.0.0.1:50321/peer-messaging/v1`

Client actions:

- `authenticate`
- `send_message`
- `submit_approval`
- `mark_read`

Server events:

- `authenticated`
- `sync_snapshot`
- `conversation_upsert`
- `message_received`
- `message_sent`
- `message_delivery_update`
- `approval_requested`
- `approval_submitted`
- `error`

Backend transport names currently used by Cylonix:

- LocalAPI: `peer-message/send`
- PeerAPI: `/v0/peer-message/message`
- native bridge event: `peerMessageEvent`

## Suggested Next Step For OpenScope Repo

If OpenClaw is going to own the client side of this loop, the practical next
step in the OpenScope repo is to build a real OpenClaw channel plugin around
the Cylonix local WebSocket contract.

The repo now includes an initial local plugin and an isolated install test path:

- `plugins/cylonix-channel/`
- `scripts/openclaw_cylonix_plugin_test.sh`

Example:

```bash
bash scripts/openclaw_cylonix_plugin_test.sh \
  --peer m1.vital-skylark.cylonix.org \
  --token "$CYLONIX_AUTH_TOKEN"
```
