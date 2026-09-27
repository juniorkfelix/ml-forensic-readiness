"""Run pytest and write results/test_report.txt with local paths redacted (spec §37, §39)."""

import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

proc = subprocess.run([sys.executable, "-m", "pytest", "-v", "-p", "no:cacheprovider", "-rs"],
                      cwd=ROOT, capture_output=True, text=True)
text = (proc.stdout + proc.stderr).replace(str(ROOT), "<project>")
header = f"ML-FREF test report\nGenerated (UTC): {datetime.now(UTC).isoformat()}\n\n"
(ROOT / "results" / "test_report.txt").write_text(header + text, encoding="utf-8")
print(text.strip().splitlines()[-1])
sys.exit(proc.returncode)
