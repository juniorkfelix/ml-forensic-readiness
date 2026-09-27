"""Phase 2: log records carry UTC timestamp, experiment_id and component."""

import re

from mlfref.logging_utils import get_logger, set_experiment_id, setup_logging


def test_log_line_format(tmp_path):
    log_file = tmp_path / "run.log"
    setup_logging("INFO", log_file, experiment_id="EXP-LF-C-05-S003")
    get_logger("train").info("epoch 1 done")
    set_experiment_id("EXP-BD-A-05-S001")
    get_logger("mlfref.attacks").warning("second message")
    for handler in get_logger("mlfref").handlers:
        handler.flush()

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    pattern = (
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z \| (INFO|WARNING) \| "
        r"(EXP-[A-Z]+-[ABC]-\d{2}-S\d{3}) \| (mlfref\.\w+) \| .+$"
    )
    assert re.match(pattern, lines[0])
    assert "EXP-LF-C-05-S003 | mlfref.train | epoch 1 done" in lines[0]
    assert "EXP-BD-A-05-S001 | mlfref.attacks | second message" in lines[1]
    setup_logging("INFO")  # release the file handle
