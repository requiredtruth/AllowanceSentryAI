import unittest

from allowancesentry.analyze import AnalysisError, UINT256_MAX, analyze_snapshot
from allowancesentry.explain import explain_local


OWNER = "0x" + "11" * 20
TOKEN_A = "0x" + "22" * 20
TOKEN_B = "0x" + "33" * 20
ACTOR_A = "0x" + "44" * 20
ACTOR_B = "0x" + "55" * 20


def snapshot(observations):
    return {
        "chain_id": 1,
        "block_number": 20_000_000,
        "block_hash": "0x" + "ab" * 32,
        "owner": OWNER,
        "source": "unit-test fixture",
        "observations": observations,
    }


class AnalyzeTests(unittest.TestCase):
    def test_unlimited_allowance_and_revocation(self) -> None:
        report = analyze_snapshot(snapshot([{
            "standard": "erc20", "token": TOKEN_A, "spender": ACTOR_A,
            "allowance": str(UINT256_MAX), "balance": "100",
        }]))
        entry = report["entries"][0]
        self.assertEqual(entry["state"], "unlimited")
        self.assertEqual(entry["attention"], "high")
        self.assertEqual(entry["revocation"]["data"][:10], "0x095ea7b3")
        self.assertEqual(len(entry["revocation"]["data"]), 138)

    def test_operator_approval_uses_false_calldata(self) -> None:
        report = analyze_snapshot(snapshot([{
            "standard": "erc721-operator", "token": TOKEN_B,
            "operator": ACTOR_B, "approved": True,
        }]))
        entry = report["entries"][0]
        self.assertEqual(entry["state"], "collection-wide-active")
        self.assertEqual(entry["revocation"]["data"][:10], "0xa22cb465")
        self.assertTrue(entry["revocation"]["data"].endswith("0" * 64))

    def test_zero_allowance_has_no_revocation(self) -> None:
        report = analyze_snapshot(snapshot([{
            "standard": "erc20", "token": TOKEN_A, "spender": ACTOR_A,
            "allowance": 0,
        }]))
        self.assertEqual(report["summary"]["active"], 0)
        self.assertEqual(report["unsigned_revocations"], [])

    def test_duplicate_pair_is_rejected(self) -> None:
        row = {"standard": "erc20", "token": TOKEN_A, "spender": ACTOR_A, "allowance": 1}
        with self.assertRaisesRegex(AnalysisError, "duplicates"):
            analyze_snapshot(snapshot([row, row.copy()]))

    def test_invalid_address_is_rejected(self) -> None:
        data = snapshot([]); data["owner"] = "0x1234"
        with self.assertRaisesRegex(AnalysisError, "20-byte"):
            analyze_snapshot(data)

    def test_ai_endpoint_must_be_loopback_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            explain_local({}, "https://example.com", "model")


if __name__ == "__main__":
    unittest.main()
