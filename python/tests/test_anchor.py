# SPDX-License-Identifier: BSD-3-Clause
"""Tests for rung 6 anchor CLIENT: non-blocking, digest-only, repointable."""
import json
import socket
import threading
import time

import pytest

from agent_action_capsule.anchor import DEFAULT_ANCHOR_ENDPOINT, anchor


FAKE_CID = "a" * 64  # 64-char hex string (valid capsule_id shape)


def test_anchor_returns_immediately():
    """anchor() must not block; verify it returns before any network timeout."""
    errors: list[Exception] = []
    t0 = time.monotonic()
    # Point at a port nothing is listening on — the POST will fail, but anchor()
    # must still return immediately (before the network call even tries).
    anchor(FAKE_CID, endpoint="http://127.0.0.1:1", timeout=0.05, on_error=errors.append)
    elapsed = time.monotonic() - t0
    # Should return in well under 10 ms; the background thread may still be running.
    assert elapsed < 0.5, f"anchor() blocked for {elapsed:.3f}s"


def _read_http_request(conn: socket.socket) -> bytes:
    """Read a full HTTP/1.1 request from a socket and return the body."""
    raw = b""
    conn.settimeout(2.0)
    # Read until we have the end-of-headers marker.
    while b"\r\n\r\n" not in raw:
        chunk = conn.recv(4096)
        if not chunk:
            break
        raw += chunk
    headers_part, _, body_so_far = raw.partition(b"\r\n\r\n")
    # Extract Content-Length to know how many body bytes to read.
    content_length = 0
    for line in headers_part.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break
    # Read remaining body bytes.
    while len(body_so_far) < content_length:
        chunk = conn.recv(content_length - len(body_so_far))
        if not chunk:
            break
        body_so_far += chunk
    return body_so_far


def test_anchor_digest_only():
    """Only capsule_id crosses the wire — no other data."""
    received_bodies: list[bytes] = []

    def _handler(conn: socket.socket) -> None:
        body = _read_http_request(conn)
        received_bodies.append(body)
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        except Exception:
            pass
        conn.close()

    # Spin up a minimal TCP server to capture what the client sends.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    srv.settimeout(2.0)

    def _serve() -> None:
        try:
            conn, _ = srv.accept()
            _handler(conn)
        except Exception:
            pass
        finally:
            srv.close()

    server_thread = threading.Thread(target=_serve, daemon=True)
    server_thread.start()

    anchor(FAKE_CID, endpoint=f"http://127.0.0.1:{port}/v1/digest")
    server_thread.join(timeout=2.0)

    assert received_bodies, "no request body captured"
    body_json = json.loads(received_bodies[-1] or b"{}")
    assert set(body_json.keys()) == {"capsule_id"}, f"unexpected fields: {set(body_json.keys())}"
    assert body_json["capsule_id"] == FAKE_CID


def test_anchor_on_error_called_on_failure():
    """When the post fails, on_error is invoked with the exception."""
    errors: list[Exception] = []
    anchor(FAKE_CID, endpoint="http://127.0.0.1:1", timeout=0.05, on_error=errors.append)
    # Give the background thread time to fail.
    deadline = time.monotonic() + 2.0
    while not errors and time.monotonic() < deadline:
        time.sleep(0.05)
    assert errors, "on_error was not called after connection refused"
    assert isinstance(errors[0], Exception)


def test_anchor_silent_on_failure_by_default():
    """Without on_error, failures are silently dropped (no exception raised)."""
    # Should not raise even though nothing is listening.
    anchor(FAKE_CID, endpoint="http://127.0.0.1:1", timeout=0.05)
    time.sleep(0.2)  # let background thread finish


def test_anchor_default_endpoint_exported():
    assert DEFAULT_ANCHOR_ENDPOINT.startswith("https://")
    assert "digest" in DEFAULT_ANCHOR_ENDPOINT


def test_anchor_repointable():
    """Passing a different endpoint routes there (not to DEFAULT_ANCHOR_ENDPOINT)."""
    received: list[str] = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    srv.settimeout(2.0)

    def _serve() -> None:
        try:
            conn, _ = srv.accept()
            raw = b""
            conn.settimeout(2.0)
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw += chunk
            received.append(raw.decode(errors="replace"))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    threading.Thread(target=_serve, daemon=True).start()
    anchor(FAKE_CID, endpoint=f"http://127.0.0.1:{port}/custom-path")
    deadline = time.monotonic() + 2.0
    while not received and time.monotonic() < deadline:
        time.sleep(0.05)
    assert received, "no request received on custom endpoint"
    assert "/custom-path" in received[0]
