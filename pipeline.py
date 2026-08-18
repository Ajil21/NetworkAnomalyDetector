"""Anomaly-detection pipeline: feature engineering → Isolation Forest → scored results."""

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "data")
RESULTS_FILE = os.path.join(OUTPUT_DIR, "results.csv")


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def _engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add per-flow and per-source-IP windowed aggregate features."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # ── Per-flow features ────────────────────────────────────────────────
    df["bytes_per_sec"] = df["bytes_sent"] / df["duration_sec"].replace(0, 0.001)
    df["packets_per_sec"] = df["packets_sent"] / df["duration_sec"].replace(0, 0.001)

    # ── 5-minute window aggregates per src_ip ────────────────────────────
    df["window"] = df["timestamp"].dt.floor("5min")

    agg = (
        df.groupby(["src_ip", "window"])
        .agg(
            flow_count=("dst_ip", "size"),
            unique_dst_ports=("dst_port", "nunique"),
            unique_dst_ips=("dst_ip", "nunique"),
            window_total_bytes=("bytes_sent", "sum"),
        )
        .reset_index()
    )

    df = df.merge(agg, on=["src_ip", "window"], how="left")

    return df


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

FEATURE_COLS = [
    "bytes_sent",
    "packets_sent",
    "duration_sec",
    "bytes_per_sec",
    "packets_per_sec",
    "flow_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "window_total_bytes",
]


def run_pipeline(
    filepath: str,
    contamination: float = 0.05,
    random_state: int = 42,
) -> pd.DataFrame:
    """Run the full anomaly-detection pipeline.

    Parameters
    ----------
    filepath : str
        Path to the input CSV (e.g. ``data/sample_traffic.csv``).
    contamination : float
        Expected proportion of anomalies (passed to IsolationForest).
    random_state : int
        Random seed for reproducibility.

    Returns
    -------
    pd.DataFrame
        Original data augmented with engineered features, ``anomaly_score``,
        and ``is_anomaly`` (1 = normal, -1 = anomaly — sklearn convention).
    """
    # Load
    df = pd.read_csv(filepath)
    print(f"[LOAD] Loaded {len(df)} rows from {filepath}")

    # Feature engineering
    df = _engineer_features(df)

    # Scale
    scaler = StandardScaler()
    X = scaler.fit_transform(df[FEATURE_COLS].fillna(0))

    # Train Isolation Forest
    iso = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=200,
        n_jobs=-1,
    )
    iso.fit(X)

    # Score
    df["anomaly_score"] = iso.decision_function(X)
    df["is_anomaly"] = iso.predict(X)  # 1 = normal, -1 = anomaly

    # Save
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    df.to_csv(RESULTS_FILE, index=False)
    print(f"[SAVE] Saved results -> {RESULTS_FILE}")

    return df


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sample_path = os.path.join(OUTPUT_DIR, "sample_traffic.csv")
    df = run_pipeline(sample_path)

    # Show top 10 most anomalous rows
    top = (
        df.loc[df["is_anomaly"] == -1]
        .sort_values("anomaly_score")
        .head(10)
    )
    print("\n[TOP 10] Most anomalous rows (lowest anomaly_score = most anomalous):\n")
    print(
        top[
            [
                "timestamp", "src_ip", "dst_ip", "dst_port",
                "protocol", "bytes_sent", "packets_sent",
                "bytes_per_sec", "unique_dst_ports", "flow_count",
                "anomaly_score", "is_anomaly",
            ]
        ].to_string(index=False)
    )
