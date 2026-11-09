"""
Custom transport example: carry PSI messages over a message queue.

queue.Queue stands in for the platform's own messaging (RabbitMQ, Kafka,
Redis Streams, an RPC framework...). Two ways to plug it in are shown:

    1. CallbackChannel: pass send/recv functions, nothing else to write.
    2. A custom class implementing the Channel protocol (send / recv).
"""

import os
import queue
import tempfile
import threading

from cryptex import CallbackChannel, CryptexError, Curve, Protocol, Psi, Role

TIMEOUT = 30


class QueueChannel:
    """Option 2: any object with send(bytes) / recv() -> bytes is a Channel"""

    def __init__(self, outbox, inbox):
        self._outbox = outbox
        self._inbox = inbox

    def send(self, msg):
        self._outbox.put(msg, timeout=TIMEOUT)

    def recv(self):
        return self._inbox.get(timeout=TIMEOUT)


def main():
    receiver_to_sender = queue.Queue()
    sender_to_receiver = queue.Queue()

    # Sender side, option 1: wrap existing functions. Data passed as a list.
    sender_channel = CallbackChannel(
        send=lambda msg: sender_to_receiver.put(msg, timeout=TIMEOUT),
        recv=lambda: receiver_to_sender.get(timeout=TIMEOUT),
    )
    sender = Psi(Protocol.ECDH, Role.SENDER, sender_channel, curve=Curve.SM2)
    threading.Thread(target=sender.run, args=(["bob", "carol", "dave"],),
                     daemon=True).start()

    # Receiver side, option 2: a custom Channel class. Data read from a CSV.
    with tempfile.TemporaryDirectory() as tmp:
        ids = os.path.join(tmp, "ids.csv")
        with open(ids, "w", encoding="utf-8") as f:
            f.write("id,name\nalice,Alice\nbob,Bob\ncarol,Carol\n")

        receiver_channel = QueueChannel(receiver_to_sender, sender_to_receiver)
        receiver = Psi(Protocol.ECDH, Role.RECEIVER, receiver_channel, curve=Curve.SM2)
        try:
            common = receiver.run(ids, column="id")
        except CryptexError as e:
            print(f"PSI failed: {e}")
            return
    print("intersection seen by the receiver:", common)


if __name__ == "__main__":
    main()
