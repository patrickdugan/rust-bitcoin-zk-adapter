"""Static checks for the example separate-UID systemd service units.

Run-time account provisioning, systemd cgroup enforcement and genuine Raito
proof verification are separate deployment acceptance tests.
"""
import configparser
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1] / "deploy" / "systemd"
NAMES = [
    "supernode-gateway.service",
    "supernode-proof-worker-broker.service",
    "supernode-raito-verifier.service",
    "supernode-statement-verifier.service",
]


def load(name: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    config.read(BASE / name, encoding="utf8")
    return config


class ServiceIsolationTemplates(unittest.TestCase):
    def test_dedicated_identities_and_kernel_lifetime_controls(self):
        services = [load(name)["Service"] for name in NAMES]
        users = [svc["User"] for svc in services]
        self.assertEqual(len(set(users)), len(NAMES))
        self.assertTrue(all(u != "root" for u in users))
        self.assertIn("supernode-gateway", users)
        for svc in services:
            self.assertEqual(svc["NoNewPrivileges"], "yes")
            self.assertEqual(svc["KillMode"], "control-group")
            self.assertEqual(svc["MemorySwapMax"], "0")
            self.assertEqual(svc["ProtectSystem"], "strict")
            self.assertEqual(svc["RestrictNamespaces"], "yes")
            self.assertEqual(svc["StateDirectoryMode"], "0700")
            self.assertTrue(svc["MemoryMax"].endswith("G"))
            self.assertGreater(int(svc["MemoryMax"][:-1]), 0)
            self.assertLessEqual(int(svc["TasksMax"]), 128)

    def test_gateway_and_peer_sockets_have_distinct_ownership(self):
        gateway, producer, verifier, statements = map(load, NAMES)
        self.assertIn("supernode-ipc", gateway["Service"]["SupplementaryGroups"])
        for unit in (producer, verifier, statements):
            svc = unit["Service"]
            self.assertEqual(svc["Group"], "supernode-ipc")
            self.assertEqual(svc["RuntimeDirectoryMode"], "0770")
            self.assertEqual(svc["UMask"], "0007")
            self.assertNotEqual(svc["User"], gateway["Service"]["User"])
            self.assertNotIn("/home", svc["ExecStart"])
        state = [u["Service"]["StateDirectory"] for u in (producer, verifier, statements)]
        runtime = [u["Service"]["RuntimeDirectory"] for u in (producer, verifier, statements)]
        self.assertEqual(len(set(state)), 3)
        self.assertEqual(len(set(runtime)), 3)
        for unit in (verifier, statements):
            self.assertEqual(unit["Service"]["RestrictAddressFamilies"], "AF_UNIX")

    def test_statement_verifier_holds_no_core_access(self):
        gateway, _, _, statements = map(load, NAMES)
        svc = statements["Service"]
        # The gateway keeps the Core credentials; the statement verifier has
        # no network namespace and its own environment file.
        self.assertEqual(svc["PrivateNetwork"], "yes")
        self.assertNotEqual(svc["EnvironmentFile"], gateway["Service"]["EnvironmentFile"])
        self.assertLessEqual(int(svc["MemoryMax"][:-1]), 4)
        self.assertIn("supernode-statement-verifier.service", gateway["Unit"]["After"])
        # Optional: the gateway still starts without statement verification.
        self.assertNotIn("supernode-statement-verifier.service", gateway["Unit"]["Requires"])

    def test_no_service_runs_shell_commands_as_root(self):
        for name in NAMES:
            service = load(name)["Service"]
            self.assertTrue(service["ExecStart"].startswith("/opt/supernode/bin/"))
            self.assertEqual(service["ProtectHome"], "yes")
            self.assertEqual(service["PrivateDevices"], "yes")
            self.assertTrue(service["EnvironmentFile"].startswith("/etc/supernode/"))


if __name__ == "__main__":
    unittest.main()
