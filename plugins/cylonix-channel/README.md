# OpenClaw Cylonix Channel Plugin

This plugin adds a `cylonix` channel to OpenClaw and sends direct messages
through the local Cylonix app WebSocket proxy.

Expected local Cylonix endpoint:

- `ws://127.0.0.1:50321/peer-messaging/v1`

Minimum OpenClaw config:

```json
{
  "plugins": {
    "enabled": true,
    "entries": {
      "cylonix": {
        "enabled": true
      }
    }
  },
  "channels": {
    "cylonix": {
      "accounts": {
        "default": {
          "enabled": true,
          "url": "ws://127.0.0.1:50321/peer-messaging/v1",
          "token": "test-token",
          "conversationTitle": "OpenClaw via Cylonix"
        }
      }
    }
  }
}
```

For the current local Cylonix behavior, the plugin treats `token` as an opaque
string and defaults to `test-token` if it is omitted. Keep the field in config
for forward compatibility if Cylonix starts validating it later.

Example send:

```bash
openclaw message send --channel cylonix \
  --target m1.vital-skylark.cylonix.org \
  --message "hello from OpenClaw via Cylonix"
```
