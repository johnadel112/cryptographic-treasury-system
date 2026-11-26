import socket
import threading
import unittest
from treasury.framing import send_json, recv_json


class FramingTests(unittest.TestCase):
    def test_round_trip(self):
        left, right = socket.socketpair()
        try:
            payload = {"type": "hello", "n": 5}
            thread = threading.Thread(target=send_json, args=(left, payload))
            thread.start()
            self.assertEqual(recv_json(right), payload)
            thread.join()
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
