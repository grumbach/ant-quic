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


class NonObservingIdsInsideCollectedSuites(unittest.TestCase):
    """Suite membership must not gate benches that never execute ant-quic."""

    def _separated_regression_shape(self, bench_id: str):
        baseline = est(100, lower=95, upper=105)
        current = est(106, lower=105.5, upper=110)  # +6%, CIs separated
        control = est(100.2, lower=95, upper=105)  # ~0.2% noise
        return gate.compare_sides(
            {bench_id: baseline},
            {bench_id: current},
            {bench_id: control},
        )

    def test_bytes_create_large_never_gates(self):
        # Replays this PR's CI false alarm: bytes/create_large +6% / 0.2% noise.
        bench_id = gate.qualify("quic_benchmarks", "bytes/create_large")
        self.assertIn(bench_id, gate.NON_GATING_BENCH_IDS)
        rows = self._separated_regression_shape(bench_id)
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(rows[0].gated)
        self.assertFalse(gate.gate_should_fail(rows))

    def test_duration_from_millis_never_gates(self):
        bench_id = gate.qualify("quic_benchmarks", "duration/from_millis")
        self.assertIn(bench_id, gate.NON_GATING_BENCH_IDS)
        rows = self._separated_regression_shape(bench_id)
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(gate.gate_should_fail(rows))

    def test_patterns_option_unwrap_or_never_gates(self):
        bench_id = gate.qualify("quic_benchmarks", "patterns/option_unwrap_or")
        self.assertIn(bench_id, gate.NON_GATING_BENCH_IDS)
        rows = self._separated_regression_shape(bench_id)
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(gate.gate_should_fail(rows))

    def test_varint_still_gates_on_same_shape(self):
        bench_id = gate.qualify("quic_benchmarks", "varint/create_small")
        self.assertIn(bench_id, gate.GATING_BENCH_IDS)
        rows = self._separated_regression_shape(bench_id)
        self.assertEqual(rows[0].status, "REGRESSION")
        self.assertTrue(gate.gate_should_fail(rows))

    def test_direct_ml_kem_public_key_never_gates(self):
        # Timed body is only Box::new([0u8; SIZE]); no ant-quic call (RC2).
        bench_id = gate.qualify("pqc_memory_pool_bench", "direct_ml_kem_public_key")
        self.assertIn(bench_id, gate.NON_GATING_BENCH_IDS)
        self.assertNotIn(bench_id, gate.GATING_BENCH_IDS)
        rows = self._separated_regression_shape(bench_id)
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(rows[0].gated)
        self.assertFalse(gate.gate_should_fail(rows))

    def test_transport_error_create_protocol_violation_never_gates(self):
        # Timed body is TransportError { ... } + String::from; no ant-quic method (RC3).
        bench_id = gate.qualify(
            "quic_benchmarks", "transport_error/create_protocol_violation"
        )
        self.assertIn(bench_id, gate.NON_GATING_BENCH_IDS)
        self.assertNotIn(bench_id, gate.GATING_BENCH_IDS)
        rows = self._separated_regression_shape(bench_id)
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(rows[0].gated)
        self.assertFalse(gate.gate_should_fail(rows))

    def test_transport_error_create_with_reason_never_gates(self):
        bench_id = gate.qualify("quic_benchmarks", "transport_error/create_with_reason")
        self.assertIn(bench_id, gate.NON_GATING_BENCH_IDS)
        self.assertNotIn(bench_id, gate.GATING_BENCH_IDS)
        rows = self._separated_regression_shape(bench_id)
        self.assertEqual(rows[0].status, "INFO")
        self.assertFalse(rows[0].gated)
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

    def test_collect_reads_benchmark_json_inside_label_dir(self):
        """Some Criterion layouts put benchmark.json under the baseline label."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite = "quic_benchmarks"
            label = "baseline"
            snap = root / suite / "varint" / "create_medium" / label
            snap.mkdir(parents=True)
            (snap / "benchmark.json").write_text(
                json.dumps(
                    {
                        "group_id": "varint",
                        "full_id": "varint/create_medium",
                        "directory_name": "varint/create_medium",
                    }
                )
            )
            (snap / "estimates.json").write_text(
                json.dumps(
                    {
                        "mean": {
                            "point_estimate": 7.0,
                            "confidence_interval": {
                                "confidence_level": 0.95,
                                "lower_bound": 6.5,
                                "upper_bound": 7.5,
                            },
                        },
                        "median": {"point_estimate": 7.0},
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
            self.assertEqual(data["quic_benchmarks::varint/create_medium"]["mean"], 7.0)

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


class InterleavedConfirmation(unittest.TestCase):
    """RC2: provisional regressions from runner drift must not fail unchanged code."""

    def test_unchanged_code_provisional_regression_cleared_by_abab(self):
        # Replays SHA 8336f413 job failure shape: pool +24.3% vs 0.0% control noise
        # while Rust/benches/deps and the executable were unchanged — drift after
        # baseline+control both ran before current.
        bench_id = gate.qualify("pqc_memory_pool_bench", "pool_ml_kem_public_key")
        baseline = est(100, lower=95, upper=105)
        control = est(100, lower=95, upper=105)  # 0% control noise
        drifted_current = est(124.3, lower=120, upper=130)
        provisional = gate.compare_sides(
            {bench_id: baseline},
            {bench_id: drifted_current},
            {bench_id: control},
        )
        self.assertEqual(provisional[0].status, "REGRESSION")
        self.assertTrue(gate.gate_should_fail(provisional))

        # ABAB interleaved pairs see the same executable on both sides → stable.
        stable = est(101, lower=96, upper=106)
        confirmed = gate.apply_interleaved_confirmation(
            provisional,
            {bench_id: control},
            [
                ({bench_id: stable}, {bench_id: est(102, lower=97, upper=107)}),
                ({bench_id: est(100.5, lower=95.5, upper=105.5)}, {bench_id: est(101.2, lower=96, upper=106)}),
            ],
        )
        self.assertEqual(confirmed[0].status, "NOISE")
        self.assertIn("interleaved confirmation", confirmed[0].reason)
        self.assertFalse(gate.gate_should_fail(confirmed))

    def test_persistent_regression_survives_abab_confirmation(self):
        bench_id = gate.qualify("pqc_memory_pool_bench", "pool_ml_kem_public_key")
        baseline = est(100, lower=95, upper=105)
        control = est(101, lower=96, upper=106)
        current = est(200, lower=190, upper=210)
        provisional = gate.compare_sides(
            {bench_id: baseline},
            {bench_id: current},
            {bench_id: control},
        )
        self.assertTrue(gate.gate_should_fail(provisional))
        confirmed = gate.apply_interleaved_confirmation(
            provisional,
            {bench_id: control},
            [
                ({bench_id: baseline}, {bench_id: current}),
                ({bench_id: est(99, lower=94, upper=104)}, {bench_id: est(198, lower=188, upper=208)}),
            ],
        )
        self.assertEqual(confirmed[0].status, "REGRESSION")
        self.assertIn("confirmed by 2 interleaved", confirmed[0].reason)
        self.assertTrue(gate.gate_should_fail(confirmed))

    def test_drifted_absolute_confirmation_baselines_preserve_noise_ratio(self):
        # Codex RC3 repro: original baseline/control 100, current 120 (REGRESSION).
        # Confirmation pairs both 150→180 with disjoint CIs. Comparing each fresh
        # baseline against the ORIGINAL control would inflate noise to ~33% and
        # wrongly clear the persistent 20% regression as NOISE. The gate must
        # preserve the original 0% noise ratio and still fail.
        bench_id = gate.qualify("pqc_memory_pool_bench", "pool_ml_kem_public_key")
        baseline = est(100, lower=95, upper=105)
        control = est(100, lower=95, upper=105)
        current = est(120, lower=115, upper=125)
        provisional = gate.compare_sides(
            {bench_id: baseline},
            {bench_id: current},
            {bench_id: control},
        )
        self.assertEqual(provisional[0].status, "REGRESSION")
        self.assertEqual(provisional[0].control_noise, 0.0)
        self.assertTrue(gate.gate_should_fail(provisional))

        pair1_b = est(150, lower=145, upper=155)
        pair1_c = est(180, lower=175, upper=185)
        pair2_b = est(150, lower=145, upper=155)
        pair2_c = est(180, lower=175, upper=185)
        # Pre-fix: original-control classification would clear (the bug).
        buggy = gate.classify(bench_id, pair1_b, pair1_c, control)
        self.assertEqual(buggy.status, "NOISE")

        confirmed = gate.apply_interleaved_confirmation(
            provisional,
            {bench_id: control},
            [
                ({bench_id: pair1_b}, {bench_id: pair1_c}),
                ({bench_id: pair2_b}, {bench_id: pair2_c}),
            ],
        )
        self.assertEqual(confirmed[0].status, "REGRESSION")
        self.assertEqual(confirmed[0].control_noise, 0.0)
        self.assertIn("confirmed by 2 interleaved", confirmed[0].reason)
        self.assertTrue(gate.gate_should_fail(confirmed))

    def test_confirm_cli_clears_unchanged_code_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bench_id = "pqc_memory_pool_bench::pool_ml_kem_public_key"
            payload = {
                "baseline.json": {
                    bench_id: {"mean": 100, "lower": 95, "upper": 105}
                },
                "control.json": {
                    bench_id: {"mean": 100, "lower": 95, "upper": 105}
                },
                "current.json": {
                    bench_id: {"mean": 124.3, "lower": 120, "upper": 130}
                },
                "a1.json": {bench_id: {"mean": 100, "lower": 95, "upper": 105}},
                "b1.json": {bench_id: {"mean": 101, "lower": 96, "upper": 106}},
                "a2.json": {bench_id: {"mean": 100.5, "lower": 95.5, "upper": 105.5}},
                "b2.json": {bench_id: {"mean": 100.8, "lower": 95.8, "upper": 105.8}},
            }
            for name, body in payload.items():
                (root / name).write_text(json.dumps(body))
            report = root / "report.md"
            rc = gate.main(
                [
                    "confirm",
                    "--baseline",
                    str(root / "baseline.json"),
                    "--control",
                    str(root / "control.json"),
                    "--current",
                    str(root / "current.json"),
                    "--pair1-baseline",
                    str(root / "a1.json"),
                    "--pair1-current",
                    str(root / "b1.json"),
                    "--pair2-baseline",
                    str(root / "a2.json"),
                    "--pair2-current",
                    str(root / "b2.json"),
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
            self.assertEqual(rc, 0)
            self.assertIn("interleaved", report.read_text())


if __name__ == "__main__":
    unittest.main()
