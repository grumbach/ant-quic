#!/usr/bin/env python3
"""Same-host, merge-base benchmark gate for ant-quic (#291).

Defects this gate must not reproduce:
1. Fail a PR on mock / non-observing benches (std-only simulations).
2. Compare against head-of-master artifacts instead of the PR merge-base.
3. Compare across runners/jobs without a same-commit control.
4. Threshold a raw mean delta while ignoring Criterion confidence intervals.
5. Fail on runner-state drift when baseline+control both ran before current
   (RC2: provisional regressions need ABAB interleaved confirmation).

The gate fails a PR only when a *gating* bench (one that executes ant-quic code)
is slower than the merge-base on the *same runner*, the 95% CIs do not overlap,
the relative delta exceeds the measured same-commit control noise for that
bench (with a small floor), *and* an interleaved confirmation still regresses.
Mock suites may still be collected for information; they never set the exit
status.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


# Suites collected in CI. Still run their Criterion binary so informational
# (non-ant-quic) benches appear in the report; only GATING_BENCH_IDS can fail.
COLLECTED_SUITES: Tuple[str, ...] = (
    "pqc_memory_pool_bench",
    "quic_benchmarks",
)

# Exact qualified ids that may fail a PR. Suite-wide allowlists are unsafe:
# quic_benchmarks also contains bytes/*, duration/*, and patterns/* which
# measure the bytes crate / std / language idioms and do not execute ant-quic
# (CI evidence: bytes/create_large +6% with 0.2% control noise on a no-Rust PR).
#
# RC2/RC3 audit (timed body must call ant-quic code):
# - varint/*: VarInt::from_u32 / Ord — YES (ant_quic::VarInt)
# - transport_error/*: TransportError { ... } + String::from — NO → NON_GATING
#   (struct literal + std string alloc/drop; no ant-quic method)
# - pool_ml_kem_public_key: PqcMemoryPool::acquire_ml_kem_public_key — YES
# - pool_ml_kem_secret_key: PqcMemoryPool::acquire_ml_kem_secret_key — YES
# - concurrent_pool_access: PqcMemoryPool::acquire_ml_kem_ciphertext — YES
# - direct_ml_kem_public_key: Box::new([0u8; SIZE]) only — NO → NON_GATING
GATING_BENCH_IDS: frozenset[str] = frozenset(
    {
        # VarInt: ant_quic public type with real method calls on the hot path.
        "quic_benchmarks::varint/create_small",
        "quic_benchmarks::varint/create_medium",
        "quic_benchmarks::varint/create_large",
        "quic_benchmarks::varint/compare",
        # PQC memory pool: ant_quic::crypto::pqc::memory_pool (observing only).
        "pqc_memory_pool_bench::pool_ml_kem_public_key",
        "pqc_memory_pool_bench::pool_ml_kem_secret_key",
        "pqc_memory_pool_bench::concurrent_pool_access",
    }
)

# Suites retained for local/informational runs. They do not observe production
# paths in a way that can justify a merge gate (issue #291 defect 1).
# connection_management: PeerId newtype + local VecDeque/RwLock mocks.
# nat_traversal_performance: tokio::sleep / Vec sort simulations, no ant-quic.
NON_GATING_SUITES: Tuple[str, ...] = (
    "connection_management",
    "nat_traversal_performance",
)

# Non-observing ids inside COLLECTED_SUITES (documented for tests/reports).
NON_GATING_BENCH_IDS: frozenset[str] = frozenset(
    {
        "quic_benchmarks::bytes/create_small",
        "quic_benchmarks::bytes/create_medium",
        "quic_benchmarks::bytes/create_large",
        "quic_benchmarks::bytes/clone_1kb",
        "quic_benchmarks::duration/from_millis",
        "quic_benchmarks::duration/as_nanos",
        "quic_benchmarks::patterns/option_unwrap_or",
        "quic_benchmarks::patterns/result_ok",
        # Struct literal + std String alloc/drop; no ant-quic method call (RC3).
        "quic_benchmarks::transport_error/create_protocol_violation",
        "quic_benchmarks::transport_error/create_with_reason",
        # std Box heap alloc + imported size constant; no pool / ant-quic call.
        "pqc_memory_pool_bench::direct_ml_kem_public_key",
    }
)

# Relative floor so tiny absolute CI gaps on nanosecond benches do not flake.
MIN_REGRESSION_RATIO = 0.05


@dataclass(frozen=True)
class Estimate:
    """Criterion mean estimate with optional confidence interval."""

    mean: float
    lower: Optional[float]
    upper: Optional[float]

    @property
    def has_ci(self) -> bool:
        return (
            self.lower is not None
            and self.upper is not None
            and math.isfinite(self.lower)
            and math.isfinite(self.upper)
            and self.lower > 0
            and self.upper >= self.lower
        )


@dataclass(frozen=True)
class Comparison:
    bench_id: str
    baseline: Estimate
    current: Estimate
    control: Optional[Estimate]
    change_ratio: float
    control_noise: float
    status: str
    gated: bool
    reason: str


def is_gating_bench_id(bench_id: str) -> bool:
    """Return True only for exact allowlisted ant-quic-observing bench ids."""
    return bench_id in GATING_BENCH_IDS


def qualify(suite: str, bench_id: str) -> str:
    return f"{suite}::{bench_id}"


def split_qualified_id(bench_id: str) -> Tuple[str, str]:
    """Split ``suite::criterion_full_id`` into suite and Criterion filter."""
    suite, sep, rest = bench_id.partition("::")
    if not sep or not suite or not rest:
        raise ValueError(f"expected suite::id, got {bench_id!r}")
    return suite, rest


def gated_regression_ids(rows: Iterable[Comparison]) -> List[str]:
    return [row.bench_id for row in rows if row.gated and row.status == "REGRESSION"]


def _ci_bounds(mean_obj: Mapping[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    ci = mean_obj.get("confidence_interval") or {}
    lower = ci.get("lower_bound")
    upper = ci.get("upper_bound")
    if isinstance(lower, (int, float)) and isinstance(upper, (int, float)):
        return float(lower), float(upper)
    return None, None


def estimate_from_criterion_mean(mean_obj: Mapping[str, Any]) -> Estimate:
    point = mean_obj.get("point_estimate")
    if not isinstance(point, (int, float)) or not math.isfinite(point) or point <= 0:
        raise ValueError(f"invalid mean point_estimate: {point!r}")
    lower, upper = _ci_bounds(mean_obj)
    return Estimate(mean=float(point), lower=lower, upper=upper)


def load_estimates_json(path: Path) -> Estimate:
    data = json.loads(path.read_text())
    return estimate_from_criterion_mean(data["mean"])


def collect_suite_estimates(criterion_root: Path, suite: str, baseline_label: str) -> Dict[str, Estimate]:
    """Collect estimates for one Criterion --save-baseline label under a suite tree."""
    root = criterion_root / suite
    if not root.is_dir():
        raise ValueError(f"missing criterion suite directory: {root}")
    found: Dict[str, Estimate] = {}
    for estimates in root.glob(f"**/{baseline_label}/estimates.json"):
        # .../<directory_name>/<label>/estimates.json
        bench_dir = estimates.parent.parent
        # Criterion may place benchmark.json beside the baseline label dir or
        # inside it depending on version / --save-baseline layout.
        meta = bench_dir / "benchmark.json"
        if not meta.is_file():
            meta = estimates.parent / "benchmark.json"
        if meta.is_file():
            identity = json.loads(meta.read_text()).get("full_id")
            if not isinstance(identity, str) or not identity:
                raise ValueError(f"invalid benchmark.json at {meta}")
        else:
            identity = bench_dir.relative_to(root).as_posix()
        key = qualify(suite, identity)
        if key in found:
            raise ValueError(f"duplicate estimate for {key}")
        found[key] = load_estimates_json(estimates)
    if not found:
        raise ValueError(f"no estimates for suite={suite} label={baseline_label} under {root}")
    return found


def collect_side(criterion_root: Path, suites: Sequence[str], label: str) -> Dict[str, Estimate]:
    merged: Dict[str, Estimate] = {}
    for suite in suites:
        merged.update(collect_suite_estimates(criterion_root, suite, label))
    return merged


def relative_change(baseline: float, current: float) -> float:
    if baseline <= 0:
        return 0.0
    return (current - baseline) / baseline


def control_noise_ratio(baseline: Estimate, control: Optional[Estimate]) -> float:
    if control is None:
        return 0.0
    return abs(relative_change(baseline.mean, control.mean))


def classify(
    bench_id: str,
    baseline: Estimate,
    current: Estimate,
    control: Optional[Estimate],
    *,
    noise_override: Optional[float] = None,
) -> Comparison:
    """Decide status for one bench. Only gating + CI-separated regressions fail.

    ``noise_override`` preserves a previously measured same-commit noise ratio
    (used by ABAB confirmation so a drifted absolute baseline cannot inflate
    the noise floor against the original control).
    """
    gated = is_gating_bench_id(bench_id)
    change = relative_change(baseline.mean, current.mean)
    noise = (
        noise_override
        if noise_override is not None
        else control_noise_ratio(baseline, control)
    )

    if not gated:
        return Comparison(
            bench_id=bench_id,
            baseline=baseline,
            current=current,
            control=control,
            change_ratio=change,
            control_noise=noise,
            status="INFO",
            gated=False,
            reason="non-gating bench (mock or non-observing); never fails the job",
        )

    if control is None:
        return Comparison(
            bench_id=bench_id,
            baseline=baseline,
            current=current,
            control=control,
            change_ratio=change,
            control_noise=noise,
            status="UNAVAILABLE",
            gated=True,
            reason="missing same-commit control; refusing to gate",
        )

    if not baseline.has_ci or not current.has_ci:
        return Comparison(
            bench_id=bench_id,
            baseline=baseline,
            current=current,
            control=control,
            change_ratio=change,
            control_noise=noise,
            status="UNAVAILABLE",
            gated=True,
            reason="missing Criterion confidence interval; refusing raw-mean gate",
        )

    # Current is statistically slower only when its CI sits entirely above baseline's.
    slower = current.lower is not None and baseline.upper is not None and current.lower > baseline.upper
    threshold = max(MIN_REGRESSION_RATIO, noise)
    if slower and change > threshold:
        return Comparison(
            bench_id=bench_id,
            baseline=baseline,
            current=current,
            control=control,
            change_ratio=change,
            control_noise=noise,
            status="REGRESSION",
            gated=True,
            reason=(
                f"non-overlapping CIs and change {change:.1%} exceeds "
                f"control noise floor {threshold:.1%}"
            ),
        )

    if slower:
        return Comparison(
            bench_id=bench_id,
            baseline=baseline,
            current=current,
            control=control,
            change_ratio=change,
            control_noise=noise,
            status="NOISE",
            gated=True,
            reason=f"CIs separated but change {change:.1%} within control noise {threshold:.1%}",
        )

    return Comparison(
        bench_id=bench_id,
        baseline=baseline,
        current=current,
        control=control,
        change_ratio=change,
        control_noise=noise,
        status="STABLE",
        gated=True,
        reason="confidence intervals overlap or current is not slower",
    )


def compare_sides(
    baseline: Mapping[str, Estimate],
    current: Mapping[str, Estimate],
    control: Mapping[str, Estimate],
    require_control: bool = True,
) -> List[Comparison]:
    if require_control and not control:
        raise ValueError("same-commit control measurements are required")
    ids = sorted(set(baseline) | set(current))
    rows: List[Comparison] = []
    for bench_id in ids:
        if bench_id not in baseline or bench_id not in current:
            rows.append(
                Comparison(
                    bench_id=bench_id,
                    baseline=baseline.get(bench_id, Estimate(0.0, None, None)),
                    current=current.get(bench_id, Estimate(0.0, None, None)),
                    control=control.get(bench_id),
                    change_ratio=0.0,
                    control_noise=0.0,
                    status="UNAVAILABLE",
                    gated=is_gating_bench_id(bench_id),
                    reason="benchmark missing on baseline or current side",
                )
            )
            continue
        rows.append(
            classify(
                bench_id,
                baseline[bench_id],
                current[bench_id],
                control.get(bench_id),
            )
        )
    return rows


def gate_should_fail(rows: Iterable[Comparison]) -> bool:
    """Fail only on gated REGRESSION rows. Mocks/info/unavailable never fail."""
    return any(row.gated and row.status == "REGRESSION" for row in rows)


def apply_interleaved_confirmation(
    provisional_rows: Sequence[Comparison],
    control: Mapping[str, Estimate],
    pairs: Sequence[Tuple[Mapping[str, Estimate], Mapping[str, Estimate]]],
) -> List[Comparison]:
    """Keep a provisional REGRESSION only if every interleaved pair still regresses.

    Runner drift after baseline+control (both measured before current) can look
    like a real regression with ~0% control noise. Re-measuring flagged ids as
    ABAB (baseline, current, baseline, current) clears unchanged-code noise.

    Confirmation pairs reuse the provisional row's control-noise ratio rather
    than recomputing noise against the original control absolute value: a
    drifted pair baseline (e.g. 150 vs original control 100) would otherwise
    inflate the noise floor and reclassify a persistent relative regression as
    NOISE.
    """
    if not pairs:
        raise ValueError("at least one interleaved confirmation pair is required")

    out: List[Comparison] = []
    for row in provisional_rows:
        if not (row.gated and row.status == "REGRESSION"):
            out.append(row)
            continue

        pair_rows: List[Comparison] = []
        missing = False
        for pair_baseline, pair_current in pairs:
            if row.bench_id not in pair_baseline or row.bench_id not in pair_current:
                missing = True
                break
            pair_rows.append(
                classify(
                    row.bench_id,
                    pair_baseline[row.bench_id],
                    pair_current[row.bench_id],
                    control.get(row.bench_id),
                    noise_override=row.control_noise,
                )
            )
        if missing:
            out.append(
                Comparison(
                    bench_id=row.bench_id,
                    baseline=row.baseline,
                    current=row.current,
                    control=row.control,
                    change_ratio=row.change_ratio,
                    control_noise=row.control_noise,
                    status="UNAVAILABLE",
                    gated=True,
                    reason=(
                        "provisional regression missing from interleaved confirmation; "
                        "refusing to fail"
                    ),
                )
            )
            continue

        if all(p.status == "REGRESSION" for p in pair_rows):
            confirmed = pair_rows[-1]
            out.append(
                Comparison(
                    bench_id=row.bench_id,
                    baseline=confirmed.baseline,
                    current=confirmed.current,
                    control=row.control,
                    change_ratio=confirmed.change_ratio,
                    control_noise=confirmed.control_noise,
                    status="REGRESSION",
                    gated=True,
                    reason=(
                        f"confirmed by {len(pair_rows)} interleaved pair(s): "
                        f"{confirmed.reason}"
                    ),
                )
            )
            continue

        cleared = pair_rows[-1]
        out.append(
            Comparison(
                bench_id=row.bench_id,
                baseline=cleared.baseline,
                current=cleared.current,
                control=row.control,
                change_ratio=cleared.change_ratio,
                control_noise=cleared.control_noise,
                status="NOISE",
                gated=True,
                reason=(
                    "provisional regression cleared by interleaved confirmation "
                    f"(pair statuses: {', '.join(p.status for p in pair_rows)})"
                ),
            )
        )
    return out


def format_report(
    rows: Sequence[Comparison],
    *,
    merge_base: str,
    head: str,
    runner: str,
    confirmation: Optional[str] = None,
) -> str:
    lines = [
        "### Same-host merge-base benchmark gate (#291)\n",
        f"- Merge-base: `{merge_base}`",
        f"- PR head: `{head}`",
        f"- Runner: `{runner}` (baseline, same-commit control, and current in one job)",
        f"- Gating benchmarks: {', '.join(sorted(GATING_BENCH_IDS))}",
        f"- Collected suites (informational ids included): {', '.join(COLLECTED_SUITES)}",
        f"- Non-gating suites: {', '.join(NON_GATING_SUITES)}",
        f"- Rule: fail only if a gating bench has non-overlapping 95% CIs, "
        f"current is slower, the relative delta exceeds max("
        f"{MIN_REGRESSION_RATIO:.0%}, same-commit control noise), and ABAB "
        f"interleaved confirmation still regresses\n",
    ]
    if confirmation:
        lines.append(f"- Confirmation: {confirmation}")
        lines.append("")
    lines.extend(
        [
            "| Benchmark | Baseline mean | Current mean | Change | Control noise | Status |",
            "|-----------|---------------|--------------|--------|---------------|--------|",
        ]
    )
    for row in rows:
        lines.append(
            "| {id} | {b:.4g} | {c:.4g} | {ch:+.1%} | {n:.1%} | {s} |".format(
                id=row.bench_id,
                b=row.baseline.mean,
                c=row.current.mean,
                ch=row.change_ratio,
                n=row.control_noise,
                s=row.status,
            )
        )
    regressions = [r for r in rows if r.gated and r.status == "REGRESSION"]
    lines.append("\n### Summary\n")
    if regressions:
        lines.append(f"**{len(regressions)} gating regression(s):**")
        for row in regressions:
            lines.append(f"- {row.bench_id}: {row.reason}")
    else:
        lines.append("No gating regressions (mocks and CI-overlapping deltas do not fail the job).")
    lines.append("")
    return "\n".join(lines)


def parse_estimates_map(path: Path) -> Dict[str, Estimate]:
    """Load a JSON object of bench_id -> {mean, lower, upper}."""
    raw = json.loads(path.read_text())
    out: Dict[str, Estimate] = {}
    for key, value in raw.items():
        out[key] = Estimate(
            mean=float(value["mean"]),
            lower=float(value["lower"]) if value.get("lower") is not None else None,
            upper=float(value["upper"]) if value.get("upper") is not None else None,
        )
    return out


def dump_estimates_map(estimates: Mapping[str, Estimate], path: Path) -> None:
    payload = {
        key: {"mean": est.mean, "lower": est.lower, "upper": est.upper}
        for key, est in sorted(estimates.items())
    }
    path.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n")


def cmd_collect(args: argparse.Namespace) -> int:
    estimates = collect_side(args.criterion_root, args.suite, args.label)
    dump_estimates_map(estimates, args.out)
    print(f"collected {len(estimates)} estimates -> {args.out}")
    return 0


def _write_regression_ids(path: Optional[Path], rows: Sequence[Comparison]) -> None:
    if path is None:
        return
    ids = gated_regression_ids(rows)
    path.write_text("".join(f"{bench_id}\n" for bench_id in ids))


def cmd_compare(args: argparse.Namespace) -> int:
    baseline = parse_estimates_map(args.baseline)
    current = parse_estimates_map(args.current)
    control = parse_estimates_map(args.control)
    rows = compare_sides(baseline, current, control, require_control=True)
    report = format_report(
        rows,
        merge_base=args.merge_base,
        head=args.head,
        runner=args.runner,
    )
    args.report.write_text(report)
    _write_regression_ids(args.regressions_out, rows)
    print(report)
    if gate_should_fail(rows):
        return 1
    return 0


def cmd_confirm(args: argparse.Namespace) -> int:
    """Re-classify provisional regressions using ABAB interleaved pair maps."""
    baseline = parse_estimates_map(args.baseline)
    current = parse_estimates_map(args.current)
    control = parse_estimates_map(args.control)
    provisional = compare_sides(baseline, current, control, require_control=True)
    pairs = [
        (parse_estimates_map(args.pair1_baseline), parse_estimates_map(args.pair1_current)),
        (parse_estimates_map(args.pair2_baseline), parse_estimates_map(args.pair2_current)),
    ]
    rows = apply_interleaved_confirmation(provisional, control, pairs)
    report = format_report(
        rows,
        merge_base=args.merge_base,
        head=args.head,
        runner=args.runner,
        confirmation="ABAB interleaved re-measure of provisional regressions",
    )
    args.report.write_text(report)
    _write_regression_ids(args.regressions_out, rows)
    print(report)
    if gate_should_fail(rows):
        return 1
    return 0


def cmd_filters(args: argparse.Namespace) -> int:
    """Print ``suite\\tfilter`` lines for Criterion-filtered confirmation runs."""
    ids = [
        line.strip()
        for line in args.regressions.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    for bench_id in ids:
        suite, filt = split_qualified_id(bench_id)
        print(f"{suite}\t{filt}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="Collect Criterion estimates for suites")
    collect.add_argument("--criterion-root", type=Path, required=True)
    collect.add_argument("--suite", action="append", required=True)
    collect.add_argument("--label", required=True)
    collect.add_argument("--out", type=Path, required=True)
    collect.set_defaults(func=cmd_collect)

    compare = sub.add_parser("compare", help="Compare baseline/control/current maps")
    compare.add_argument("--baseline", type=Path, required=True)
    compare.add_argument("--control", type=Path, required=True)
    compare.add_argument("--current", type=Path, required=True)
    compare.add_argument("--report", type=Path, required=True)
    compare.add_argument("--regressions-out", type=Path, default=None)
    compare.add_argument("--merge-base", required=True)
    compare.add_argument("--head", required=True)
    compare.add_argument("--runner", default="unknown")
    compare.set_defaults(func=cmd_compare)

    confirm = sub.add_parser(
        "confirm",
        help="Confirm provisional regressions with ABAB interleaved pair maps",
    )
    confirm.add_argument("--baseline", type=Path, required=True)
    confirm.add_argument("--control", type=Path, required=True)
    confirm.add_argument("--current", type=Path, required=True)
    confirm.add_argument("--pair1-baseline", type=Path, required=True)
    confirm.add_argument("--pair1-current", type=Path, required=True)
    confirm.add_argument("--pair2-baseline", type=Path, required=True)
    confirm.add_argument("--pair2-current", type=Path, required=True)
    confirm.add_argument("--report", type=Path, required=True)
    confirm.add_argument("--regressions-out", type=Path, default=None)
    confirm.add_argument("--merge-base", required=True)
    confirm.add_argument("--head", required=True)
    confirm.add_argument("--runner", default="unknown")
    confirm.set_defaults(func=cmd_confirm)

    filters = sub.add_parser(
        "filters",
        help="Emit suite/filter pairs for Criterion-filtered confirmation runs",
    )
    filters.add_argument("--regressions", type=Path, required=True)
    filters.set_defaults(func=cmd_filters)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"bench_gate failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
