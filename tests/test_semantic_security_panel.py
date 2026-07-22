import json
import tempfile
import unittest
from pathlib import Path

from scripts.aggregate_semantic_security_panel import aggregate_panel


def verdict(label):
    return {
        "label": label,
        "counts_for_ssc": label in {"Reference-equivalent", "Alternative secure"},
        "counts_for_overfit_rate": False,
        "confidence": "High",
        "evidence_used": [],
        "missing_evidence": [],
    }


class SemanticSecurityPanelTests(unittest.TestCase):
    def write_summary(self, root, name, rows):
        path = root / f"{name}.json"
        path.write_text(json.dumps(rows), encoding="utf-8")
        return name, path

    def test_three_model_majority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            specs = [
                self.write_summary(root, "a", [{"instance_id": "x", "verdict": verdict("Alternative secure")}]),
                self.write_summary(root, "b", [{"instance_id": "x", "verdict": verdict("Alternative secure")}]),
                self.write_summary(root, "c", [{"instance_id": "x", "verdict": verdict("Incorrect/harmful")}]),
            ]
            summary, incomplete = aggregate_panel(specs)
        self.assertEqual(incomplete, 0)
        self.assertEqual(summary[0]["verdict"]["label"], "Alternative secure")
        self.assertTrue(summary[0]["verdict"]["counts_for_ssc"])

    def test_three_way_tie_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            specs = [
                self.write_summary(root, "a", [{"instance_id": "x", "verdict": verdict("Alternative secure")}]),
                self.write_summary(root, "b", [{"instance_id": "x", "verdict": verdict("Partial repair")}]),
                self.write_summary(root, "c", [{"instance_id": "x", "verdict": verdict("Incorrect/harmful")}]),
            ]
            summary, incomplete = aggregate_panel(specs)
        self.assertEqual(incomplete, 0)
        self.assertEqual(summary[0]["verdict"]["label"], "Inconclusive")
        self.assertFalse(summary[0]["verdict"]["counts_for_ssc"])

    def test_single_model_one_round(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            specs = [self.write_summary(root, "a", [{"instance_id": "x", "verdict": verdict("Reference-equivalent")}])]
            summary, incomplete = aggregate_panel(specs)
        self.assertEqual(incomplete, 0)
        self.assertEqual(summary[0]["verdict"]["label"], "Reference-equivalent")

    def test_missing_vote_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            specs = [
                self.write_summary(root, "a", [{"instance_id": "x", "verdict": verdict("Alternative secure")}]),
                self.write_summary(root, "b", []),
            ]
            summary, incomplete = aggregate_panel(specs)
        self.assertEqual(incomplete, 1)
        self.assertIsNone(summary[0]["verdict"])
        self.assertEqual(summary[0]["error"], "incomplete judge panel")


if __name__ == "__main__":
    unittest.main()
