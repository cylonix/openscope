import crypto from "node:crypto";
import net from "node:net";

const DEFAULT_URL = "ws://127.0.0.1:50321/peer-messaging/v1";
const DEFAULT_ACCOUNT_ID = "default";
const DEFAULT_TITLE = "OpenClaw via Cylonix";
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_TOKEN = "test-token";
const CHANNEL_ID = "cylonix";
const TARGET_PREFIXES = new Set(["user", "peer", "device", "conversation", "direct"]);

function listAccountIds(cfg) {
  const accounts = cfg?.channels?.cylonix?.accounts ?? {};
  return Object.entries(accounts)
    .filter(([, account]) => account?.enabled !== false)
    .map(([accountId]) => accountId);
}

function resolveAccount(cfg, accountId) {
  const accounts = cfg?.channels?.cylonix?.accounts ?? {};
  const resolved = accounts[accountId ?? DEFAULT_ACCOUNT_ID] ?? accounts[DEFAULT_ACCOUNT_ID];
  return resolved && resolved.enabled !== false ? resolved : undefined;
}

function normalizeTarget(rawTarget) {
  if (typeof rawTarget === "string") {
    const value = rawTarget.trim();
    if (!value) {
      return "";
    }
    const idx = value.indexOf(":");
    if (idx > 0) {
      const prefix = value.slice(0, idx).toLowerCase();
      if (TARGET_PREFIXES.has(prefix)) {
        return value.slice(idx + 1);
      }
    }
    return value || undefined;
  }

  if (rawTarget && typeof rawTarget === "object") {
    const candidate =
      rawTarget.target ??
      rawTarget.to ??
      rawTarget.id ??
      rawTarget.peer ??
      rawTarget.peerId ??
      rawTarget.peer_id ??
      rawTarget.conversation_id ??
      rawTarget.conversationId;
    return normalizeTarget(candidate);
  }

  return "";
}

function sendJson(ws, value) {
  ws.sendText(JSON.stringify(value));
}

function looksLikePeerTarget(target) {
  return Boolean(normalizeTarget(target));
}

function buildWsUpgradeRequest(url, key) {
  const port = url.port || "80";
  const path = `${url.pathname || "/"}${url.search || ""}`;
  return [
    `GET ${path} HTTP/1.1`,
    `Host: ${url.hostname}:${port}`,
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Key: ${key}`,
    "Sec-WebSocket-Version: 13",
    "",
    ""
  ].join("\r\n");
}

class RawWebSocketClient {
  constructor(socket, timeoutMs) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.buffer = Buffer.alloc(0);
    this.waiters = [];
    this.closed = false;
    this.closeReason = "";

    this.socket.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.flush();
    });
    this.socket.on("close", () => {
      this.closed = true;
      this.rejectWaiters(new Error(this.closeReason || "websocket closed"));
    });
    this.socket.on("error", (error) => {
      this.rejectWaiters(error);
    });
  }

  rejectWaiters(error) {
    while (this.waiters.length > 0) {
      const waiter = this.waiters.shift();
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  }

  flush() {
    while (true) {
      const frame = this.tryParseFrame();
      if (!frame) {
        return;
      }
      if (frame.opcode === 0x8) {
        this.closed = true;
        this.closeReason = frame.payload.toString("utf8");
        this.rejectWaiters(new Error(this.closeReason || "websocket closed"));
        try {
          this.socket.end();
        } catch {}
        return;
      }
      const waiter = this.waiters.shift();
      if (waiter) {
        clearTimeout(waiter.timer);
        waiter.resolve(frame);
      }
    }
  }

  tryParseFrame() {
    if (this.buffer.length < 2) {
      return null;
    }
    const first = this.buffer[0];
    const second = this.buffer[1];
    const opcode = first & 0x0f;
    let offset = 2;
    let length = second & 0x7f;
    const masked = (second & 0x80) !== 0;

    if (length === 126) {
      if (this.buffer.length < offset + 2) {
        return null;
      }
      length = this.buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (this.buffer.length < offset + 8) {
        return null;
      }
      const bigLength = this.buffer.readBigUInt64BE(offset);
      length = Number(bigLength);
      offset += 8;
    }

    let mask;
    if (masked) {
      if (this.buffer.length < offset + 4) {
        return null;
      }
      mask = this.buffer.subarray(offset, offset + 4);
      offset += 4;
    }

    if (this.buffer.length < offset + length) {
      return null;
    }

    let payload = this.buffer.subarray(offset, offset + length);
    this.buffer = this.buffer.subarray(offset + length);

    if (masked) {
      payload = Buffer.from(payload);
      for (let i = 0; i < payload.length; i += 1) {
        payload[i] ^= mask[i % 4];
      }
    }

    return { opcode, payload };
  }

  sendText(text) {
    const payload = Buffer.from(text, "utf8");
    const mask = crypto.randomBytes(4);
    const header = [];
    header.push(Buffer.from([0x81]));
    if (payload.length < 126) {
      header.push(Buffer.from([0x80 | payload.length]));
    } else if (payload.length < 65536) {
      const length = Buffer.alloc(3);
      length[0] = 0x80 | 126;
      length.writeUInt16BE(payload.length, 1);
      header.push(length);
    } else {
      const length = Buffer.alloc(9);
      length[0] = 0x80 | 127;
      length.writeBigUInt64BE(BigInt(payload.length), 1);
      header.push(length);
    }
    const masked = Buffer.from(payload);
    for (let i = 0; i < masked.length; i += 1) {
      masked[i] ^= mask[i % 4];
    }
    this.socket.write(Buffer.concat([...header, mask, masked]));
  }

  receiveFrame(timeoutMs = this.timeoutMs) {
    const frame = this.tryParseFrame();
    if (frame) {
      return Promise.resolve(frame);
    }
    if (this.closed) {
      return Promise.reject(new Error(this.closeReason || "websocket closed"));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiters.findIndex((waiter) => waiter.resolve === resolve);
        if (index >= 0) {
          this.waiters.splice(index, 1);
        }
        reject(new Error("timed out waiting for websocket frame"));
      }, timeoutMs);
      this.waiters.push({ resolve, reject, timer });
    });
  }

  async close() {
    try {
      this.socket.end();
    } catch {}
  }
}

function openWebSocket(urlString, timeoutMs) {
  const url = new URL(urlString);
  if (url.protocol !== "ws:") {
    throw new Error(`unsupported protocol for cylonix channel: ${url.protocol}`);
  }
  const port = Number(url.port || 80);
  const key = crypto.randomBytes(16).toString("base64");
  const request = buildWsUpgradeRequest(url, key);

  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: url.hostname, port });
    let settled = false;
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`timed out connecting to ${urlString}`));
      }
    }, timeoutMs);

    socket.on("connect", () => {
      socket.write(request);
    });

    socket.on("data", (chunk) => {
      if (settled) {
        return;
      }
      buffer = Buffer.concat([buffer, chunk]);
      const marker = buffer.indexOf("\r\n\r\n");
      if (marker === -1) {
        return;
      }
      const head = buffer.subarray(0, marker).toString("utf8");
      if (!head.startsWith("HTTP/1.1 101")) {
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(new Error(`websocket upgrade failed: ${head.split("\r\n")[0]}`));
        return;
      }
      const remaining = buffer.subarray(marker + 4);
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners("data");
      const client = new RawWebSocketClient(socket, timeoutMs);
      if (remaining.length > 0) {
        client.buffer = Buffer.concat([client.buffer, remaining]);
      }
      resolve(client);
    });

    socket.on("error", (error) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(error);
      }
    });

    socket.on("close", () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error("websocket closed during upgrade"));
      }
    });
  });
}

async function waitForEvent(ws, eventName, timeoutMs) {
  while (true) {
    const frame = await ws.receiveFrame(timeoutMs);
    if (frame.opcode !== 0x1) {
      continue;
    }
    const payload = JSON.parse(frame.payload.toString("utf8"));
    if (payload?.type === "error") {
      throw new Error(payload?.payload?.message ?? payload?.message ?? JSON.stringify(payload));
    }
    if (payload?.type === eventName) {
      return payload;
    }
  }
}

async function waitForMatchingEvent(ws, eventName, timeoutMs, predicate) {
  while (true) {
    const payload = await waitForEvent(ws, eventName, timeoutMs);
    if (predicate(payload)) {
      return payload;
    }
  }
}

async function sendViaCylonix({ account, target, text, logger }) {
  const url = account?.url || DEFAULT_URL;
  const token = account?.token || DEFAULT_TOKEN;
  const conversationTitle = account?.conversationTitle || DEFAULT_TITLE;
  const timeoutMs = Number(account?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const resolvedTarget = normalizeTarget(target);

  if (!resolvedTarget) {
    throw new Error("a peer target is required for the cylonix channel");
  }
  if (!text || !String(text).trim()) {
    throw new Error("message text is required");
  }

  logger?.info?.(`cylonix: sending to ${resolvedTarget} via ${url}`);

  const ws = await openWebSocket(url, timeoutMs);
  try {
    sendJson(ws, {
      type: "authenticate",
      payload: {
        token
      }
    });
    await waitForEvent(ws, "authenticated", timeoutMs);
    await waitForEvent(ws, "sync_snapshot", timeoutMs);

    sendJson(ws, {
      type: "send_message",
      payload: {
        conversation_id: resolvedTarget,
        conversation_title: conversationTitle,
        text: String(text)
      }
    });

    const sent = await waitForMatchingEvent(ws, "message_sent", timeoutMs, (event) => {
      const eventConversationId = event?.conversation_id ?? event?.payload?.conversation_id;
      const eventMessage = event?.payload?.message;
      const eventText = eventMessage?.text;
      return eventConversationId === resolvedTarget && eventText === String(text);
    });
    const messageId = sent?.message_id ?? sent?.payload?.message?.id ?? sent?.payload?.message_id ?? sent?.payload?.id;
    if (!messageId) {
      throw new Error("cylonix send acknowledged without a message id");
    }
    return {
      ok: true,
      via: CHANNEL_ID,
      channel: CHANNEL_ID,
      messageId,
      target: resolvedTarget,
      raw: sent
    };
  } finally {
    await ws.close();
  }
}

const plugin = {
  id: CHANNEL_ID,
  meta: {
    label: "Cylonix",
    selectionLabel: "Cylonix peer messaging",
    docsPath: "/channels/cylonix",
    blurb: "Direct messaging through the local Cylonix app."
  },
  capabilities: {
    chatTypes: ["direct"]
  },
  messaging: {
    normalizeTarget,
    targetResolver: {
      looksLikeId: looksLikePeerTarget,
      hint: "<peer-hostname|stable-node-id>"
    }
  },
  config: {
    listAccountIds,
    resolveAccount
  },
  outbound: {
    deliveryMode: "direct",
    sendText: async (ctx) => {
      const account = resolveAccount(ctx?.cfg ?? {}, ctx?.accountId);
      const result = await sendViaCylonix({
        account,
        target: ctx?.to ?? ctx?.target,
        text: ctx?.text,
        logger: ctx?.logger
      });
      return result;
    }
  }
};

export default function register(api) {
  api.registerChannel({ plugin });
}
