# Cylonix App Test Cases For OpenClaw Messaging Channel

This document turns the transport guide in `docs/cylonix_peer_message_test_guide.md`
into concrete test cases for validating the OpenClaw messaging channel through the
Cylonix app.

The target path under test is:

```text
OpenClaw local channel client
  -> Cylonix app local WebSocket
  -> Cylonix peerMessage LocalAPI
  -> Cylonix peer transport
  -> remote peer
  -> remote Cylonix app inbox/thread UI
```

## Scope

These test cases focus on the current v1 contract:

- local WebSocket endpoint at `ws://127.0.0.1:50321/peer-messaging/v1`
- authenticate first
- send text with `send_message`
- optional approval flow with `submit_approval`
- read-state sync with `mark_read`
- Cylonix app must remain open
- sender and receiver are expected to be under the same user account/tailnet

## Assumptions

- the local host already has the Cylonix app running
- the sender device is the machine where OpenClaw connects
- the receiver device is a second device with a compatible Cylonix build
- both devices are online and signed into the same currently supported account/tailnet
- the tester can obtain the sender auth token and receiver peer reference from Cylonix

## Test Data

Use stable, easy-to-recognize values during manual validation:

- sender title: `OpenClaw Test Sender`
- receiver title: `OpenClaw Test Receiver`
- text message A: `OpenClaw smoke test: hello from sender`
- text message B: `OpenClaw follow-up test: second message`
- approval prompt: `Approve test action?`
- approval response: `approved`

Use the receiver FQDN as the default peer reference unless stable node ID coverage
is the explicit goal of the case.

## Pass Criteria

Treat the channel as healthy when all of the following hold:

- OpenClaw connects to the local Cylonix WebSocket
- authentication succeeds
- sender receives expected server events
- sender Cylonix UI reflects the outbound thread state
- receiver Cylonix UI reflects the inbound thread state
- thread contents remain consistent on both devices

## Core Test Matrix

| ID | Area | Goal |
| --- | --- | --- |
| OC-MSG-001 | Handshake | Verify local WebSocket authentication succeeds |
| OC-MSG-002 | Handshake | Verify authentication fails with a bad token |
| OC-MSG-003 | Send text | Verify first text message creates a thread |
| OC-MSG-004 | Send text | Verify follow-up text appends to the same thread |
| OC-MSG-005 | Routing | Verify receiver FQDN works as `conversation_id` |
| OC-MSG-006 | Routing | Verify receiver `StableNodeID` also works |
| OC-MSG-007 | Receive/UI | Verify receiver inbox unread state updates |
| OC-MSG-008 | Read state | Verify `mark_read` clears unread state |
| OC-MSG-009 | Approval | Verify approval request/response path works |
| OC-MSG-010 | Resilience | Verify app-closed receiver does not receive in v1 |
| OC-MSG-011 | Resilience | Verify sender-side failure on invalid peer reference |
| OC-MSG-012 | Session | Verify reconnect and resync behavior |

## Detailed Test Cases

### OC-MSG-001: Authenticate to the local Cylonix WebSocket

Purpose:
Confirm OpenClaw can establish a valid session with the local Cylonix app.

Preconditions:

- Cylonix app is open on the sender
- `Peer Messages` screen is visible
- tester has copied the current auth token

Steps:

1. Connect OpenClaw to `ws://127.0.0.1:50321/peer-messaging/v1`.
2. Send `authenticate` with the copied token.
3. Log all frames received after connect.

Expected results:

- connection succeeds
- server emits `authenticated`
- server emits `sync_snapshot`
- snapshot shows `proxy.is_running = true`
- no `error` event is received

### OC-MSG-002: Reject an invalid auth token

Purpose:
Confirm the local proxy enforces authentication.

Preconditions:

- same as OC-MSG-001

Steps:

1. Connect to the local WebSocket.
2. Send `authenticate` with an intentionally bad or stale token.
3. Observe the response and connection state.

Expected results:

- authentication does not succeed
- client does not receive a valid `authenticated` event for the bad token
- server returns an error or closes the session
- no message send is allowed on that session

### OC-MSG-003: Send the first text message to a receiver by FQDN

Purpose:
Validate the basic OpenClaw-to-Cylonix text send path.

Preconditions:

- OC-MSG-001 passed
- receiver Cylonix app is open to `Peer Messages`
- receiver FQDN is known

Steps:

1. Send `send_message` with:
   - `conversation_id = <receiver-fqdn>`
   - `conversation_title = OpenClaw Test Receiver`
   - `text = OpenClaw smoke test: hello from sender`
2. Observe sender-side events.
3. Inspect sender and receiver Cylonix UI.

Expected results:

- sender receives `message_sent`
- sender UI creates a new thread for the receiver
- sender thread shows message A
- receiver inbox shows a new conversation
- receiver thread shows message A

### OC-MSG-004: Append a second text message to the same thread

Purpose:
Verify thread continuity instead of duplicate thread creation.

Preconditions:

- OC-MSG-003 passed

Steps:

1. Send a second `send_message` to the same `conversation_id`.
2. Use `text = OpenClaw follow-up test: second message`.
3. Inspect sender and receiver thread history.

Expected results:

- sender receives another `message_sent`
- no duplicate conversation is created for the same peer
- both messages appear in order in the sender thread
- both messages appear in order in the receiver thread

### OC-MSG-005: Route successfully using receiver FQDN

Purpose:
Confirm the preferred v1 routing identifier works consistently.

Preconditions:

- receiver FQDN is known exactly

Steps:

1. Authenticate.
2. Send a text message using the receiver FQDN as the `conversation_id`.
3. Repeat at least twice across fresh sessions.

Expected results:

- each session can send successfully
- each send reaches the same receiver thread
- no unexpected route changes occur

### OC-MSG-006: Route successfully using receiver StableNodeID

Purpose:
Confirm the alternate routing identifier is also supported.

Preconditions:

- receiver StableNodeID is known exactly

Steps:

1. Authenticate.
2. Send a text message using the StableNodeID as `conversation_id`.
3. Inspect sender events and receiver UI.

Expected results:

- sender receives `message_sent`
- receiver gets the message
- thread is usable even when the route key is StableNodeID

### OC-MSG-007: Receiver unread state updates on inbound message

Purpose:
Verify the Cylonix app behaves like a usable OpenClaw inbox.

Preconditions:

- receiver starts with the target conversation not currently open

Steps:

1. Send a new inbound text from the sender.
2. Leave the receiver on the inbox list first.
3. Observe unread indicators before opening the thread.

Expected results:

- receiver conversation appears or moves to the top
- unread count increments
- thread preview reflects the new message
- optional local notification may appear if enabled

### OC-MSG-008: Mark a conversation as read

Purpose:
Verify OpenClaw can cooperate with Cylonix read-state behavior.

Preconditions:

- OC-MSG-007 passed
- there is at least one unread message in the receiver thread

Steps:

1. Open the receiver thread in Cylonix and confirm unread state exists.
2. Trigger the expected read flow, either by UI or by sending `mark_read` if the client supports it.
3. Return to the inbox list if needed.

Expected results:

- unread badge clears
- conversation remains present
- no message content is lost
- sender/receiver state stays internally consistent after the read update

### OC-MSG-009: Approval request and response flow

Purpose:
Validate the secondary approval-style interaction needed for OpenClaw actions.

Preconditions:

- text messaging path is already working

Steps:

1. Trigger an approval-style message from the sender path.
2. Observe whether the receiver Cylonix UI renders it distinctly from plain text.
3. Respond from the receiver using the supported approval action.
4. Observe sender-side events.

Expected results:

- receiver gets an approval-oriented message or prompt
- receiver can submit a response successfully
- sender observes the corresponding approval event such as `approval_submitted`
- resulting thread history remains readable and correctly ordered

### OC-MSG-010: Receiver app closed while message is sent

Purpose:
Validate the known v1 limitation explicitly.

Preconditions:

- sender path is healthy

Steps:

1. Close the Cylonix app on the receiver.
2. Send a text message from the sender.
3. Reopen the receiver app and inspect the inbox.

Expected results:

- missing immediate delivery while the receiver app is closed is treated as expected behavior for v1
- test should record whether the message is dropped, delayed, or only appears after reopen
- no false pass should be recorded for real-time delivery in this condition

### OC-MSG-011: Invalid receiver reference produces a send failure

Purpose:
Verify bad routing data fails loudly instead of silently misrouting messages.

Preconditions:

- sender has a healthy authenticated session

Steps:

1. Send `send_message` using a fake FQDN or invalid StableNodeID.
2. Observe sender-side events and UI.
3. Confirm the intended receiver does not receive anything.

Expected results:

- sender receives an `error`, delivery failure, or lack of `message_sent`
- receiver gets no message
- test log captures the exact invalid peer reference used

### OC-MSG-012: Reconnect and resync after session drop

Purpose:
Verify the local OpenClaw client can recover from a broken WebSocket session.

Preconditions:

- at least one conversation already exists

Steps:

1. Authenticate and observe the initial `sync_snapshot`.
2. Disconnect the client session.
3. Reconnect and authenticate again.
4. Inspect the new `sync_snapshot`.

Expected results:

- reconnect succeeds without changing the auth token unless the app rotated it
- client receives a fresh `sync_snapshot`
- existing conversation state is visible after reconnect
- client can send another message successfully after reconnect

## Suggested Execution Order

Run the cases in this order for fastest signal:

1. OC-MSG-001
2. OC-MSG-003
3. OC-MSG-004
4. OC-MSG-007
5. OC-MSG-008
6. OC-MSG-012
7. OC-MSG-002
8. OC-MSG-011
9. OC-MSG-006
10. OC-MSG-009
11. OC-MSG-010

This order proves the happy path first, then covers failure and edge conditions.

## Logging Checklist

For each case, capture:

- test case ID
- date and time
- sender device name
- receiver device name
- receiver peer reference used
- auth result
- all server events observed
- sender UI result
- receiver UI result
- pass or fail
- notes and screenshots if behavior is surprising

## Out Of Scope For This Set

These are useful later, but should not block the first OpenClaw channel validation pass:

- attachments and file transfer
- large message payload limits
- multi-receiver or group semantics
- offline queue guarantees
- notification delivery guarantees across all Apple states
- cross-account or cross-tailnet policy cases
