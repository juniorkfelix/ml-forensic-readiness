"""SHA-256 hashing and canonical serialisation (stdlib only).

Every hash in ML-FREF is SHA-256 over bytes. Structured data is first serialised
with ``canonical_json`` (sorted keys, compact separators, UTF-8). Dataset
manifests are canonicalised by sorting records on ``sample_id``, so the manifest
hash depends on content only, not on record order (spec §9).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

HASH_ALGORITHM = "SHA-256"
_CHUNK = 1024 * 1024


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, non-ASCII preserved."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_json(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def sha256_file(path: str | Path) -> str:
    """Stream a file through SHA-256 (constant memory)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_manifest_records(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Sort manifest records by ``sample_id``; reject duplicate or missing IDs."""
    ordered = sorted((dict(r) for r in records), key=lambda r: r["sample_id"])
    ids = [r["sample_id"] for r in ordered]
    if len(ids) != len(set(ids)):
        raise ValueError("manifest contains duplicate sample_id values")
    return ordered


def manifest_hash(records: Iterable[Mapping[str, Any]]) -> str:
    """SHA-256 of the canonical (sorted, canonically serialised) manifest records."""
    return sha256_json(canonical_manifest_records(records))


def verify_hash(expected: str, observed: str) -> bool:
    """Case-insensitive comparison of hex digests."""
    return expected.strip().lower() == observed.strip().lower()
