"""Application logging for ML-FREF.

Every log record includes a UTC timestamp, level, experiment_id, component
(logger name) and message:

    2026-09-27T20:31:05.123456Z | INFO | EXP-LF-C-05-S003 | mlfref.train | epoch 3 ...

This is ordinary *application* logging and exists in every pipeline mode,
including A (conventional). It is NOT the forensic evidence store: pipeline C
writes forensic events to a separate SQLite database (mlfref.forensic).
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

_ROOT = "mlfref"
_NO_EXPERIMENT = "-"


class _ExperimentFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.experiment_id = _NO_EXPERIMENT

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "experiment_id"):
            record.experiment_id = self.experiment_id
        return True


class _UTCFormatter(logging.Formatter):
    def formatTime(
        self, record: logging.LogRecord, datefmt: str | None = None
    ) -> str:  # noqa: N802
        ts = datetime.fromtimestamp(record.created, tz=UTC)
        return ts.isoformat(timespec="microseconds").replace("+00:00", "Z")


_FORMAT = "%(asctime)s | %(levelname)s | %(experiment_id)s | %(name)s | %(message)s"
_filter = _ExperimentFilter()


def setup_logging(
    level: str = "INFO",
    log_file: str | Path | None = None,
    experiment_id: str | None = None,
) -> logging.Logger:
    """Configure the ``mlfref`` logger hierarchy (idempotent: replaces old handlers)."""
    root = logging.getLogger(_ROOT)
    root.setLevel(level.upper())
    root.propagate = False
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    formatter = _UTCFormatter(_FORMAT)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(_filter)
        root.addHandler(handler)

    # Route warnings.warn(...) (e.g. PyTorch non-determinism warnings) into the log.
    logging.captureWarnings(True)
    warnings_logger = logging.getLogger("py.warnings")
    for handler in list(warnings_logger.handlers):
        warnings_logger.removeHandler(handler)
    for handler in handlers:
        warnings_logger.addHandler(handler)

    set_experiment_id(experiment_id)
    return root


def set_experiment_id(experiment_id: str | None) -> None:
    _filter.experiment_id = experiment_id or _NO_EXPERIMENT


def get_logger(component: str) -> logging.Logger:
    """Logger for a component, e.g. get_logger('train') -> 'mlfref.train'."""
    name = component if component.startswith(_ROOT) else f"{_ROOT}.{component}"
    return logging.getLogger(name)


# --------------------------------------------------------------------------- evidence app log

PIPELINE_LOGGER = f"{_ROOT}.pipeline"


def get_pipeline_logger(component: str) -> logging.Logger:
    """Logger for a *pipeline* component (its output is investigator-visible app.log)."""
    return logging.getLogger(f"{PIPELINE_LOGGER}.{component}")


def attach_evidence_log(path: str | Path, run_ref: str) -> logging.Handler:
    """Write pipeline-component log records to an investigator-visible ``app.log``.

    Only loggers under ``mlfref.pipeline`` reach this handler, so harness and attack
    messages (which may reveal the attack) are never written to evidence. The run is
    identified by the opaque ``run_ref`` (``RUN-<uuid>``) baked into the format,
    never by the human-readable experiment ID (D-021).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(
        _UTCFormatter(f"%(asctime)s | %(levelname)s | {run_ref} | %(name)s | %(message)s")
    )
    handler.setLevel(logging.INFO)
    logger = logging.getLogger(PIPELINE_LOGGER)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return handler


def detach_evidence_log(handler: logging.Handler) -> None:
    logging.getLogger(PIPELINE_LOGGER).removeHandler(handler)
    handler.close()
