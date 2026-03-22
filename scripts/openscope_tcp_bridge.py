#!/usr/bin/env python3
# Copyright (c) EZBLOCK Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import selectors
import socket
import threading


def pump(left: socket.socket, right: socket.socket) -> None:
    sel = selectors.DefaultSelector()
    sel.register(left, selectors.EVENT_READ, right)
    sel.register(right, selectors.EVENT_READ, left)
    try:
        while True:
            events = sel.select()
            if not events:
                continue
            for key, _ in events:
                src = key.fileobj
                dst = key.data
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    finally:
        sel.close()
        for conn in (left, right):
            try:
                conn.close()
            except OSError:
                pass


def serve(listen_host: str, listen_port: int, unix_socket_path: str) -> None:
    if not os.path.exists(unix_socket_path):
        raise SystemExit(f"unix socket not found: {unix_socket_path}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen()
    print(f"openscope tcp bridge listening on {listen_host}:{listen_port} -> {unix_socket_path}", flush=True)
    try:
        while True:
            client, _ = server.accept()
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                upstream.connect(unix_socket_path)
            except OSError:
                client.close()
                upstream.close()
                continue
            threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
    finally:
        server.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=42357)
    parser.add_argument("--unix-socket", required=True)
    args = parser.parse_args()
    serve(args.listen_host, args.listen_port, args.unix_socket)


if __name__ == "__main__":
    main()
