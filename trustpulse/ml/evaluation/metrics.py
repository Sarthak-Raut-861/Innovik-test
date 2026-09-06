"""Offline evaluation utilities.

Used to characterise the prototype honestly: what it catches, what it misses and
how late. These are engineering measurements, not scientific claims — the sample
sizes in a demo are far too small to generalise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

import pandas as pd


@dataclass
class EvaluationReport:
    """Classification quality of the trust model on a labelled sample."""

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    detection_latencies_ms: List[float] = field(default_factory=list)
    tci_by_label: Dict[str, List[float]] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)

    @property
    def mean_detection_latency_ms(self) -> float:
        return (
            sum(self.detection_latencies_ms) / len(self.detection_latencies_ms)
            if self.detection_latencies_ms
            else 0.0
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "sample_size": self.total,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "f1": round(self.f1, 4),
            "mean_detection_latency_ms": round(self.mean_detection_latency_ms, 2),
            "mean_tci_benign": round(_mean(self.tci_by_label.get("benign", [])), 2),
            "mean_tci_compromised": round(_mean(self.tci_by_label.get("compromised", [])), 2),
        }

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )


def evaluate_predictions(
    rows: Sequence[Dict[str, object]],
    flag_threshold: float = 50.0,
) -> EvaluationReport:
    """Score labelled observations.

    ``rows`` items need ``label`` ("benign"|"compromised"), ``tci`` and optionally
    ``detection_latency_ms``.
    """
    report = EvaluationReport()
    for row in rows:
        label = str(row.get("label", "")).lower()
        tci = float(row.get("tci", 0.0))  # type: ignore[arg-type]
        flagged = tci < flag_threshold
        latency = row.get("detection_latency_ms")
        if latency is not None:
            report.detection_latencies_ms.append(float(latency))  # type: ignore[arg-type]
        report.tci_by_label.setdefault(label, []).append(tci)

        if label == "compromised":
            if flagged:
                report.true_positives += 1
            else:
                report.false_negatives += 1
        else:
            if flagged:
                report.false_positives += 1
            else:
                report.true_negatives += 1
    return report


def threshold_sweep(
    rows: Sequence[Dict[str, object]], thresholds: Sequence[float]
) -> List[Dict[str, object]]:
    """Precision/recall/FPR across candidate TCI flag thresholds."""
    table: List[Dict[str, object]] = []
    for threshold in thresholds:
        report = evaluate_predictions(rows, flag_threshold=float(threshold))
        table.append({"threshold": float(threshold), **report.to_dict()})
    return table


def session_frame(observations: Sequence[Dict[str, object]]) -> pd.DataFrame:
    """Pandas view of a TCI time series, used for drift reporting."""
    frame = pd.DataFrame(list(observations))
    if frame.empty:
        return frame
    if "tci" in frame.columns:
        frame["tci"] = pd.to_numeric(frame["tci"], errors="coerce")
    if "observed_at" in frame.columns:
        frame["observed_at"] = pd.to_datetime(frame["observed_at"], errors="coerce", utc=True)
        frame = frame.sort_values("observed_at")
    return frame


def drop_summary(frame: pd.DataFrame, tci_column: str = "tci") -> Dict[str, object]:
    """Describes how fast trust fell during a session (demo + tuning aid)."""
    if frame.empty or tci_column not in frame.columns:
        return {"samples": 0}
    series = frame[tci_column].dropna()
    if series.empty:
        return {"samples": 0}
    peak = float(series.max())
    final = float(series.iloc[-1])
    below = series[series < 50]
    first_drop_index = below.index[0] if not below.empty else None
    samples_to_critical = (
        int(frame.index.get_loc(first_drop_index)) + 1 if first_drop_index is not None else None
    )
    return {
        "samples": int(len(series)),
        "peak_tci": peak,
        "final_tci": final,
        "total_drop": round(peak - final, 2),
        "samples_to_below_50": samples_to_critical,
    }


def _mean(values: Sequence[float]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def confusion_matrix(report: EvaluationReport) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Rows = actual (compromised, benign); columns = predicted (flagged, ok)."""
    return (
        (report.true_positives, report.false_negatives),
        (report.false_positives, report.true_negatives),
    )
