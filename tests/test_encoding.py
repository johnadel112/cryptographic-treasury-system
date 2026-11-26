import unittest
from treasury.encoding import canonical_json


class EncodingTests(unittest.TestCase):
    def test_canonical_json_sorts_keys_and_removes_spaces(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), b'{"a":1,"b":2}')


if __name__ == "__main__":
    unittest.main()
