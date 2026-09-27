"""Evidence instrumentation available to pipeline components in one run.

Pipelines share one code path. What differs is which evidence sinks are active:

    A conventional : application log only
    B provenance   : application log + MLflow tracker
    C forensic     : application log + MLflow tracker + forensic logger

Pipeline components (deployment, inference service, ...) receive an
``Instrumentation`` and write to whichever sinks exist, so the ML behaviour is
identical across modes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from mlfref.logging_utils import get_pipeline_logger


@dataclass
class Instrumentation:
    mode: str
    run_ref: str
    tracker: Any = None  # mlfref.provenance.mlflow_tracker.MlflowTracker (B, C)
    forensic: Any = None  # mlfref.forensic.logger.ForensicLogger (C)

    def app_log(self, component: str) -> logging.Logger:
        return get_pipeline_logger(component)

    @property
    def has_provenance(self) -> bool:
        return self.tracker is not None

    @property
    def has_forensic(self) -> bool:
        return self.forensic is not None
