"""Unit checks for bounded Supernode benchmark helpers."""
import unittest

from tools.benchmark_supernode import percentiles, require_hash, loopback_url


class BenchmarkHelpersTest(unittest.TestCase):
    def test_percentiles_for_sparse_sample(self):
        self.assertEqual(percentiles([]), {})
        data = percentiles([1, 2, 3])
        self.assertEqual(data["n"], 3)
        self.assertEqual(data["p50_ms"], 2)
        self.assertAlmostEqual(data["p95_ms"], 2.9)

    def test_strict_hash(self):
        self.assertEqual(require_hash("AB" * 32), "ab" * 32)
        with self.assertRaises(ValueError):
            require_hash("0xff")

    def test_loopback_credentials_rejected(self):
        self.assertEqual(loopback_url("http://127.0.0.1:8332"), "http://127.0.0.1:8332")
        for url in ["https://example.com", "http://example.com",
                    "http://name:password@localhost:8332", "http://192.168.1.20:8332"]:
            with self.assertRaises(ValueError):
                loopback_url(url)


if __name__ == "__main__":
    unittest.main()
