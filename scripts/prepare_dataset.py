"""Prepare CIFAR-10 (Phase 3): download, record integrity, build clean data stores.

Steps:
  1. Download CIFAR-10 into ``dataset.data_dir`` if absent (torchvision verifies the
     archive MD5). Download time is measured and reported separately (spec §43).
  2. First run: write the SHA-256 of every official file to
     ``data/manifests/cifar10_raw_integrity.json``. Later runs: VERIFY against it and
     abort on any mismatch. The official files are never modified.
  3. Build the clean pipeline data stores ``data/clean/cifar10_train.npz`` (from
     data_batch_1..5 only) and ``data/clean/cifar10_test.npz`` (from test_batch only).
  4. Write ``data/manifests/cifar10_clean_summary.json`` (sizes, class distribution,
     channel statistics, content digests, sources) and a sample grid figure.

Usage:
    python scripts/prepare_dataset.py [--config config/experiment.yaml]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mlfref.config import CIFAR10_CLASSES, load_config  # noqa: E402
from mlfref.data import cifar  # noqa: E402
from mlfref.logging_utils import get_logger, setup_logging  # noqa: E402

log = get_logger("prepare_dataset")

INTEGRITY_FILE = "cifar10_raw_integrity.json"
SUMMARY_FILE = "cifar10_clean_summary.json"
TRAIN_STORE = "cifar10_train.npz"
TEST_STORE = "cifar10_test.npz"


def save_sample_grid(arrays: cifar.CifarArrays, path: Path, per_class: int = 8) -> list[int]:
    """Grid of the first ``per_class`` training images of each class (official order)."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(len(CIFAR10_CLASSES), per_class, figsize=(per_class, 10.5))
    shown: list[int] = []
    for c, name in enumerate(CIFAR10_CLASSES):
        idx = [int(i) for i in (arrays.labels == c).nonzero()[0][:per_class]]
        shown += [int(arrays.sample_ids[i]) for i in idx]
        for j, i in enumerate(idx):
            ax = axes[c, j]
            ax.imshow(arrays.images[i], interpolation="nearest")
            ax.set_xticks([])
            ax.set_yticks([])
            if j == 0:
                ax.set_ylabel(name, rotation=0, ha="right", va="center", fontsize=10)
    fig.suptitle("CIFAR-10 training set: first 8 images per class (official order)", fontsize=11)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=300)
    fig.savefig(path.with_suffix(".svg"))
    plt.close(fig)
    return shown


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default=str(PROJECT_ROOT / "config" / "experiment.yaml"))
    args = parser.parse_args()

    cfg = load_config(args.config)
    setup_logging(cfg["logging"]["level"], PROJECT_ROOT / "logs" / "prepare_dataset.log")
    data_dir = PROJECT_ROOT / cfg["dataset"]["data_dir"]
    manifests = PROJECT_ROOT / cfg["output"]["manifests_dir"]
    clean_dir = PROJECT_ROOT / "data" / "clean"

    # 1. download (timed separately; excluded from all pipeline measurements)
    t0 = time.perf_counter()
    already_present = (data_dir / cifar.RAW_SUBDIR).is_dir()
    cifar.download_cifar10(data_dir)
    download_seconds = time.perf_counter() - t0
    log.info("CIFAR-10 available (already present: %s, %.1fs)", already_present, download_seconds)

    # 2. integrity of the official files
    integrity_path = manifests / INTEGRITY_FILE
    if integrity_path.exists():
        expected = json.loads(integrity_path.read_text(encoding="utf-8"))["sha256"]
        result = cifar.verify_raw_integrity(data_dir, expected)
        if not all(result.values()):
            log.error(
                "official CIFAR-10 files changed: %s", [k for k, v in result.items() if not v]
            )
            return 1
        log.info("official CIFAR-10 files verified against %s", integrity_path.name)
    else:
        record = {
            "dataset": "CIFAR-10 (python version)",
            "source": "https://www.cs.toronto.edu/~kriz/cifar-10-python.tar.gz",
            "hash_algorithm": "SHA-256",
            "recorded_at_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
            "sha256": cifar.raw_integrity_record(data_dir),
        }
        manifests.mkdir(parents=True, exist_ok=True)
        integrity_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        log.info("recorded SHA-256 of official files in %s", integrity_path.name)

    # 3. clean data stores
    t1 = time.perf_counter()
    train = cifar.load_official_split(data_dir, "train")
    test = cifar.load_official_split(data_dir, "test")
    cifar.write_store(clean_dir / TRAIN_STORE, train)
    cifar.write_store(clean_dir / TEST_STORE, test)
    store_seconds = time.perf_counter() - t1

    # 4. summary + figure
    stats = cifar.channel_statistics(train.images)
    summary = {
        "created_at_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
        "clean_dataset_id": cfg["dataset"]["clean_dataset_id"],
        "train": {
            "store": f"data/clean/{TRAIN_STORE}",
            "source_files": list(cifar.TRAIN_FILES),
            "num_samples": len(train),
            "class_distribution": cifar.class_distribution(train.labels),
            "content_digest_sha256": cifar.content_digest(train),
            "channel_statistics": stats,
        },
        "test": {
            "store": f"data/clean/{TEST_STORE}",
            "source_files": list(cifar.TEST_FILES),
            "num_samples": len(test),
            "class_distribution": cifar.class_distribution(test.labels),
            "content_digest_sha256": cifar.content_digest(test),
        },
        "normalisation_constants_used": {"mean": cifar.CIFAR10_MEAN, "std": cifar.CIFAR10_STD},
        "timing_seconds": {
            "download_or_check": round(download_seconds, 2),
            "build_stores": round(store_seconds, 2),
        },
    }
    (manifests / SUMMARY_FILE).write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # 5. clean dataset version (harness reference record, spec §8)
    from mlfref.config import config_hash
    from mlfref.data.manifest import write_manifest
    from mlfref.data.versioning import create_version, save_version

    alias = cfg["dataset"]["clean_dataset_id"]
    version, records = create_version(
        train, configuration_hash=config_hash(cfg), harness_alias=alias
    )
    write_manifest(manifests / f"{alias}.manifest.json", version.dataset_id, records)
    save_version(version, manifests / f"{alias}.version.json")
    print(
        f"clean version: {alias} = {version.dataset_id} "
        f"(manifest_sha256 {version.manifest_sha256[:16]}...)"
    )

    fig_path = PROJECT_ROOT / "results" / "figures" / "cifar10_clean_samples.png"
    shown = save_sample_grid(train, fig_path)
    from mlfref.reporting.metadata import record_output_metadata

    record_output_metadata(
        fig_path,
        source_data=[f"data/clean/{TRAIN_STORE}"],
        experiments=[],
        metric="none (illustrative dataset samples)",
        generation_script="scripts/prepare_dataset.py",
        description=f"First 8 training images per class; sample_ids {shown[:3]}... (80 total)",
    )

    print(f"train: {len(train)} samples  digest={summary['train']['content_digest_sha256'][:16]}")
    print(f"test : {len(test)} samples  digest={summary['test']['content_digest_sha256'][:16]}")
    print(f"train class distribution: {summary['train']['class_distribution']}")
    print(f"channel mean={stats['mean']} std={stats['std']}")
    print(f"figure: {fig_path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
