#!/usr/bin/env python3
"""Regression tests for the #291 benchmark gate.

These tests encode the four defects: they fail under the old raw-mean /
mock / cross-runner rules and pass with the new gate.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import bench_gate as gate


def est(mean, lower=None, upper=None):
    if lower is None:
        lower = mean * 0.95
    if upper is None:
        upper = mean * 1.05
    return gate.Estimate(mean=mean, lower=lower, upper=upper)


class MockBenchNeverFails(unittest.TestCase):
    """Defect 1: connection_management-style mocks must not fail the job."""

    def test_process_events_style_mock_delta_is_info_only(self):
        # Replays the #275 false alarm shape: +226% on a mock suite id.
        bench_id = gate.qualify("connection_management", "event_processing/process_events/10")
        baseline = {bench_id: est(88)}
        current = {bench_id: est(288)}  # ~+227%
        control = {bench_id: est(88)}
        rows = gate.compare_sides(baseline, current, control)
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(rows[0].gated)
        self.assertFalse(gate.gate_should_fail(rows))

    def test_nat_traversal_performance_mock_never_gates(self):
        bench_id = gate.qualify("nat_traversal_performance", "candidate_discovery/10")
        rows = gate.compare_sides(
            {bench_id: est(100)},
            {bench_id: est(500)},
            {bench_id: est(100)},
        )
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(gate.gate_should_fail(rows))


class MergeBaseAndControlRequired(unittest.TestCase):
    """Defects 2–3: refuse to gate without same-commit control; report labels."""

    def test_missing_control_is_unavailable_not_regression(self):
        bench_id = gate.qualify("quic_benchmarks", "varint/create_small")
        row = gate.classify(bench_id, est(100), est(200), control=None)
        self.assertEqual(row.status, "UNAVAILABLE")
        self.assertFalse(gate.gate_should_fail([row]))

    def test_compare_sides_requires_control_map(self):
        bench_id = gate.qualify("quic_benchmarks", "varint/create_small")
        with self.assertRaisesRegex(ValueError, "same-commit control"):
            gate.compare_sides(
                {bench_id: est(100)},
                {bench_id: est(200)},
                {},
                require_control=True,
            )

    def test_report_states_merge_base_not_head_of_master(self):
        bench_id = gate.qualify("quic_benchmarks", "varint/create_small")
        rows = gate.compare_sides(
            {bench_id: est(100)},
            {bench_id: est(101)},
            {bench_id: est(100)},
        )
        text = gate.format_report(
            rows,
            merge_base="abc123mergebase",
            head="def456prhead",
            runner="ubuntu-latest-same-job",
        )
        self.assertIn("abc123mergebase", text)
        self.assertIn("def456prhead", text)
        self.assertIn("same-commit control", text)
        self.assertNotIn("head-of-master", text)


class ConfidenceIntervalGate(unittest.TestCase):
    """Defect 4: raw mean deltas with overlapping CIs must not fail."""

    def test_overlapping_cis_with_large_mean_delta_are_stable(self):
        bench_id = gate.qualify("pqc_memory_pool_bench", "pool_ml_kem_public_key")
        # Means differ by 20%, but CIs overlap → old gate would REGRESSION.
        baseline = est(100, lower=80, upper=130)
        current = est(120, lower=90, upper=150)
        control = est(100, lower=80, upper=130)
        rows = gate.compare_sides(
            {bench_id: baseline},
            {bench_id: current},
            {bench_id: control},
        )
        self.assertEqual(rows[0].status, "STABLE")
        self.assertFalse(gate.gate_should_fail(rows))

    def test_separated_cis_within_control_noise_are_noise_not_fail(self):
        bench_id = gate.qualify("quic_benchmarks", "varint/create_small")
        baseline = est(100, lower=95, upper=105)
        # Control already moved +12% on the same commit.
        control = est(112, lower=107, upper=117)
        current = est(112, lower=107, upper=117)
        rows = gate.compare_sides(
            {bench_id: baseline},
            {bench_id: current},
            {bench_id: control},
        )
        self.assertEqual(rows[0].status, "NOISE")
        self.assertFalse(gate.gate_should_fail(rows))

    def test_true_gating_regression_still_fails(self):
        bench_id = gate.qualify("pqc_memory_pool_bench", "pool_ml_kem_public_key")
        baseline = est(100, lower=95, upper=105)
        control = est(101, lower=96, upper=106)  # ~1% noise
        current = est(200, lower=190, upper=210)  # clearly slower
        rows = gate.compare_sides(
            {bench_id: baseline},
            {bench_id: current},
            {bench_id: control},
        )
        self.assertEqual(rows[0].status, "REGRESSION")
        self.assertTrue(gate.gate_should_fail(rows))

    def test_missing_ci_refuses_raw_mean_gate(self):
        bench_id = gate.qualify("quic_benchmarks", "varint/create_small")
        baseline = gate.Estimate(mean=100, lower=None, upper=None)
        current = gate.Estimate(mean=200, lower=None, upper=None)
        control = est(100)
        rows = gate.compare_sides(
            {bench_id: baseline},
            {bench_id: current},
            {bench_id: control},
        )
        self.assertEqual(rows[0].status, "UNAVAILABLE")
        self.assertFalse(gate.gate_should_fail(rows))


class CollectAndCompareCli(unittest.TestCase):
    def test_collect_from_criterion_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite = "quic_benchmarks"
            label = "baseline"
            snap = root / suite / "varint" / "create_small" / label
            snap.mkdir(parents=True)
            (snap.parent / "benchmark.json").write_text(
                json.dumps(
                    {
                        "group_id": "varint",
                        "full_id": "varint/create_small",
                        "directory_name": "varint/create_small",
                    }
                )
            )
            (snap / "estimates.json").write_text(
                json.dumps(
                    {
                        "mean": {
                            "point_estimate": 42.0,
                            "confidence_interval": {
                                "confidence_level": 0.95,
                                "lower_bound": 40.0,
                                "upper_bound": 44.0,
                            },
                        },
                        "median": {"point_estimate": 42.0},
                    }
                )
            )
            out = root / "out.json"
            rc = gate.main(
                [
                    "collect",
                    "--criterion-root",
                    str(root),
                    "--suite",
                    suite,
                    "--label",
                    label,
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            key = "quic_benchmarks::varint/create_small"
            self.assertIn(key, data)
            self.assertEqual(data[key]["mean"], 42.0)

    def test_compare_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = {
                "pqc_memory_pool_bench::pool_ml_kem_public_key": {
                    "mean": 100,
                    "lower": 95,
                    "upper": 105,
                }
            }
            bad_current = {
                "pqc_memory_pool_bench::pool_ml_kem_public_key": {
                    "mean": 200,
                    "lower": 190,
                    "upper": 210,
                }
            }
            control = {
                "pqc_memory_pool_bench::pool_ml_kem_public_key": {
                    "mean": 101,
                    "lower": 96,
                    "upper": 106,
                }
            }
            for name, payload in (
                ("baseline.json", good),
                ("control.json", control),
                ("current_ok.json", good),
                ("current_bad.json", bad_current),
            ):
                (root / name).write_text(json.dumps(payload))

            report = root / "report.md"
            rc_ok = gate.main(
                [
                    "compare",
                    "--baseline",
                    str(root / "baseline.json"),
                    "--control",
                    str(root / "control.json"),
                    "--current",
                    str(root / "current_ok.json"),
                    "--report",
                    str(report),
                    "--merge-base",
                    "m1",
                    "--head",
                    "h1",
                    "--runner",
                    "test",
                ]
            )
            self.assertEqual(rc_ok, 0)

            rc_bad = gate.main(
                [
                    "compare",
                    "--baseline",
                    str(root / "baseline.json"),
                    "--control",
                    str(root / "control.json"),
                    "--current",
                    str(root / "current_bad.json"),
                    "--report",
                    str(report),
                    "--merge-base",
                    "m1",
                    "--head",
                    "h1",
                    "--runner",
                    "test",
                ]
            )
            self.assertEqual(rc_bad, 1)


class OldGateWouldFailNewGatePasses(unittest.TestCase):
    """End-to-end shape of the #275 false positive under both rules."""

    def test_old_raw_mean_rule_flags_mock_new_gate_does_not(self):
        mock_id = gate.qualify("connection_management", "event_processing/process_events/10")
        baseline_mean, current_mean = 88.0, 235.0
        old_change = (current_mean - baseline_mean) / baseline_mean * 100
        self.assertGreater(old_change, 10)  # old compare-benchmarks.py threshold

        rows = gate.compare_sides(
            {mock_id: est(baseline_mean)},
            {mock_id: est(current_mean)},
            {mock_id: est(baseline_mean)},
        )
        self.assertFalse(gate.gate_should_fail(rows))


if __name__ == "__main__":
    unittest.main()
