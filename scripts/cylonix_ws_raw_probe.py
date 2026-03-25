#!/usr/bin/env python3

import argparse
import base64
import json
import os
import socket
import struct
import sys


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return data
        data += chunk
    return data


def recv_frame(sock: socket.socket):
    header = recv_exact(sock, 2)
    if len(header) < 2:
        return None
    b1, b2 = header
    fin = (b1 >> 7) & 1
    opcode = b1 & 0x0F
    masked = (b2 >> 7) & 1
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return {
        "fin": fin,
        "opcode": opcode,
        "payload": payload,
    }


def send_text(sock: socket.socket, text: str) -> None:
    payload = text.encode("utf-8")
    mask = os.urandom(4)
    header = bytearray()
    header.append(0x81)
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < (1 << 16):
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=50321)
    parser.add_argument("--path", default="/peer-messaging/v1")
    parser.add_argument("--token", required=True)
    args = parser.parse_args()

    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {args.path} HTTP/1.1\r\n"
        f"Host: {args.host}:{args.port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )

    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.sendall(request.encode())
        response = sock.recv(4096)
        print(response.decode("utf-8", "replace"))

        auth = json.dumps(
            {
                "type": "authenticate",
                "payload": {"token": args.token},
            }
        )
        print(f"SEND {auth}")
        send_text(sock, auth)
        sock.settimeout(5)

        while True:
            frame = recv_frame(sock)
            if frame is None:
                print("EOF")
                return 1
            payload = frame["payload"]
            if frame["opcode"] == 1:
                print("TEXT", payload.decode("utf-8", "replace"))
            elif frame["opcode"] == 8:
                print("CLOSE", payload)
                return 1
            else:
                print("FRAME", frame["opcode"], payload)


if __name__ == "__main__":
    sys.exit(main())
