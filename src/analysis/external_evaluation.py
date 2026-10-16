# external_evaluation.py
"""
Utility for external evaluation of the trained URL model.

Provides a single function ``evaluate_external`` that accepts a dataset
containing URLs and ground‑truth labels, runs inference with the existing
model (via a supplied ``predict_func``), and returns standard classification
metrics.

The implementation **never** touches model training – it only calls the
prediction function supplied by the caller.  This guarantees that the
evaluation cannot unintentionally fit or modify the model.
"""

from __future__ import annotations

import csv
import os
from typing import Callable, Dict, Iterable, List, Tuple, Union

# Optional imports – they are only required when the caller provides a
# pandas DataFrame.  The module works without pandas.
try:
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None  # type: ignore

# ``sklearn`` is used for metric calculation if available; otherwise we fall
# back to a minimal pure‑Python implementation.
try:
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        confusion_matrix,
    )
except Exception:  # pragma: no cover
    accuracy_score = precision_score = recall_score = f1_score = confusion_matrix = None  # type: ignore

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _load_dataset(
    data: Union[str, "pd.DataFrame"],
) -> Tuple[List[str], List[int]]:
    """Load URLs and labels from a CSV file path or a pandas DataFrame.

    Parameters
    ----------
    data: str | pandas.DataFrame
        If ``str`` – interpreted as a path to a CSV file with columns ``url``
        and ``label``.  If a DataFrame – the same column names are expected.

    Returns
    -------
    Tuple[List[str], List[int]]
        Two parallel lists – URLs and integer labels (0 or 1).

    Raises
    ------
    ValueError
        If the required columns are missing or if any URL entry is empty.
    """

    # CSV path handling – we avoid any network access; the caller provides a
    # local file.  Minimal validation is performed.
    if isinstance(data, str):
        if not os.path.isfile(data):
            raise ValueError(f"Dataset file not found: {data}")
        with open(data, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    else:
        if pd is None:
            raise ImportError("pandas is required when passing a DataFrame")
        rows = data.to_dict(orient="records")

    if not rows:
        raise ValueError("Dataset is empty")

    urls: List[str] = []
    labels: List[int] = []
    for i, row in enumerate(rows, start=1):
        url = row.get("url")
        label = row.get("label")
        if url is None or str(url).strip() == "":
            raise ValueError(f"Missing URL at row {i}")
        if label is None:
            raise ValueError(f"Missing label at row {i}")
        # Normalise label to integer 0/1 – any non‑zero value is treated as 1.
        try:
            lbl_int = int(label)
        except Exception as exc:
            raise ValueError(f"Invalid label at row {i}: {label}") from exc
        if lbl_int not in (0, 1):
            raise ValueError(f"Label must be 0 or 1 at row {i}, got {lbl_int}")
        urls.append(str(url))
        labels.append(lbl_int)
    return urls, labels


def _default_predict(url: str, predict_func: Callable[[str], Dict]) -> int:
    """Run the supplied ``predict_func`` and convert its output to a binary label.

    The prediction function is expected to return a dictionary with at least
    the keys ``model_available`` (bool) and ``probability`` (float or ``None``).
    A probability ≥ 0.5 is interpreted as the positive class (label ``1``).
    If the model is unavailable the function falls back to ``0`` – this is a
    safe default that avoids raising during bulk evaluation.
    """
    result = predict_func(url)
    prob = result.get("probability")
    # When the model is unavailable ``prob`` may be ``None`` – treat as non‑phishing.
    return int(prob is not None and prob >= 0.5)


def _compute_metrics(
    y_true: List[int], y_pred: List[int]
) -> Dict[str, Union[float, Tuple[int, int, int, int]]]:
    """Calculate accuracy, precision, recall, F1 and confusion matrix.

    If ``sklearn`` is present we delegate to it; otherwise we implement the
    formulas directly.  The confusion matrix is returned as a 4‑tuple
    ``(tn, fp, fn, tp)`` to keep the output simple and JSON‑serialisable.
    """
    if confusion_matrix is not None:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
    else:
        # Manual implementation – safe for binary labels.
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
        total = len(y_true)
        acc = (tp + tn) / total if total else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        )
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": (tn, fp, fn, tp),
    }


def evaluate_external(
    dataset: Union[str, "pd.DataFrame"],
    predict_func: Callable[[str], Dict],
) -> Dict[str, Union[float, Tuple[int, int, int, int]]]:
    """External evaluation of the URL model.

    Parameters
    ----------
    dataset : str | pandas.DataFrame
        Path to a CSV file *or* a DataFrame containing two columns:
        ``url`` (the raw URL string) and ``label`` (binary ground‑truth, 0/1).
    predict_func : Callable[[str], dict]
        Function that performs model inference for a single URL.  It must return
        a dictionary compatible with :func:`src.models.url_model_inference.
        predict_url` – at minimum the keys ``model_available`` and ``probability``.

    Returns
    -------
    dict
        Mapping with keys ``accuracy``, ``precision``, ``recall``, ``f1`` and
        ``confusion_matrix``.  The confusion matrix is a ``(tn, fp, fn, tp)``
        tuple.

    Raises
    ------
    ValueError
        If the dataset is malformed (missing columns, empty URLs, or labels).
    ImportError
        If a pandas DataFrame is supplied but pandas is not installed.
    """
    # Load and validate the dataset – any issues raise early, keeping the
    # evaluation pure and side‑effect free.
    urls, labels = _load_dataset(dataset)

    # Ensure we have both positive and negative samples; many metric formulas
    # (especially precision/recall) are undefined for a single‑class dataset.
    if len(set(labels)) < 2:
        raise ValueError(
            "Both classes (0 and 1) must be present in the evaluation dataset"
        )

    # Run inference *without* modifying the model.  ``_default_predict`` safely
    # maps the model's probability output to a binary label.
    predictions = [_default_predict(u, predict_func) for u in urls]

    # Compute and return the metrics.
    return _compute_metrics(labels, predictions)

# The module purposefully does not expose any training utilities and does not
# import any training‑related code.  This guarantees that the external evaluation
# remains a read‑only operation on the existing model.
