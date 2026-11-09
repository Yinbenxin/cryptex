"""
Message channels used to carry protocol messages between two parties.

The core library does no network IO. Any object implementing the `Channel`
protocol (`send(bytes)` and `recv() -> bytes`) can carry PSI messages, so
platforms can plug in their own transport (HTTP, gRPC, message queues...).

Built-in implementations:
    CallbackChannel  wraps a pair of send/recv functions
    TcpChannel       length-prefixed TCP, a reference implementation
    MemoryChannel    in-process pair, for tests

Who listens and who connects is independent of the PSI role: either the
sender or the receiver may own the listening port.
"""

import socket
import struct
import threading
import time
from collections import deque
from typing import Protocol as _Protocol

_LEN = struct.Struct(">Q")

# Upper bound on a single incoming message, guards against memory exhaustion
# from a malformed or malicious length prefix.
DEFAULT_MAX_MESSAGE_SIZE = 1 << 30


class Channel(_Protocol):
    """Transport contract for two-party protocols

    Implementations must:
        - deliver each message whole (preserve message boundaries)
        - deliver messages in order
        - carry empty messages (b"") as real messages
        - block in recv() until a message arrives, or raise on
          timeout/disconnect

    Messages are opaque bytes. Authentication and encryption of the link are
    the transport's responsibility.
    """

    def send(self, msg: bytes) -> None:
        ...

    def recv(self) -> bytes:
        ...


class ChannelClosed(ConnectionError):
    """The peer closed the connection"""


class CallbackChannel:
    """Channel built from user-supplied send/recv functions

    The quickest way to plug a platform's own messaging into Psi:

        ch = CallbackChannel(send=platform.send_bytes, recv=platform.recv_bytes)
        Psi(Protocol.ECDH, Role.SENDER, ch).run(items)
    """

    def __init__(self, send, recv, close=None):
        self._send = send
        self._recv = recv
        self._close = close

    def send(self, msg):
        self._send(bytes(msg))

    def recv(self):
        msg = self._recv()
        if not isinstance(msg, (bytes, bytearray, memoryview)):
            raise TypeError(f"recv callback must return bytes, got {type(msg).__name__}")
        return bytes(msg)

    def close(self):
        if self._close is not None:
            self._close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class TcpChannel:
    """Length-prefixed message channel over a connected TCP socket"""

    def __init__(self, sock, max_message_size=DEFAULT_MAX_MESSAGE_SIZE):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = sock
        self._max = max_message_size
        self.bytes_sent = 0
        self.bytes_received = 0

    @classmethod
    def listen(cls, host="0.0.0.0", port=0, timeout=None, on_listening=None,
               **kwargs):
        """Listen on (host, port) and accept exactly one peer

        Args:
            host: Bind address
            port: Bind port, 0 picks a free port
            timeout: Seconds to wait for the peer (None waits forever); also
                used as the per-operation timeout afterwards
            on_listening: Optional callback receiving the bound port, useful
                with port=0
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(1)
            if on_listening is not None:
                on_listening(server.getsockname()[1])
            server.settimeout(timeout)
            sock, _ = server.accept()
        sock.settimeout(timeout)
        return cls(sock, **kwargs)

    @classmethod
    def connect(cls, host, port, timeout=None, retry_interval=0.2, **kwargs):
        """Connect to a listening peer, retrying until it is up

        Args:
            host: Peer address
            port: Peer port
            timeout: Total seconds to keep retrying (None retries forever);
                also used as the per-operation timeout afterwards
            retry_interval: Seconds between connection attempts
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                break
            except (ConnectionRefusedError, socket.timeout):
                if deadline is not None and time.monotonic() >= deadline:
                    raise
                time.sleep(retry_interval)
        sock.settimeout(timeout)
        return cls(sock, **kwargs)

    def send(self, msg):
        self._sock.sendall(_LEN.pack(len(msg)) + msg)
        self.bytes_sent += len(msg)

    def recv(self):
        (length,) = _LEN.unpack(self._recv_exact(_LEN.size))
        if length > self._max:
            raise ValueError(
                f"incoming message of {length} bytes exceeds limit {self._max}"
            )
        msg = self._recv_exact(length)
        self.bytes_received += length
        return msg

    def _recv_exact(self, n):
        buf = bytearray(n)
        view = memoryview(buf)
        got = 0
        while got < n:
            k = self._sock.recv_into(view[got:])
            if k == 0:
                raise ChannelClosed("peer closed the connection")
            got += k
        return bytes(buf)

    def close(self):
        self._sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class MemoryChannel:
    """In-process channel pair, for tests and single-process demos"""

    def __init__(self, inbox, outbox, cond):
        self._inbox = inbox
        self._outbox = outbox
        self._cond = cond

    @classmethod
    def pair(cls):
        a, b = deque(), deque()
        cond = threading.Condition()
        return cls(a, b, cond), cls(b, a, cond)

    def send(self, msg):
        with self._cond:
            self._outbox.append(bytes(msg))
            self._cond.notify_all()

    def recv(self, timeout=None):
        with self._cond:
            if not self._cond.wait_for(lambda: self._inbox, timeout):
                raise TimeoutError("no message received")
            return self._inbox.popleft()

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
