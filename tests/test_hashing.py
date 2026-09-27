"""SHA-256 hashing and canonical manifest hashing (spec §9)."""

import random

import pytest

from mlfref.forensic.hashing import (
    canonical_json,
    manifest_hash,
    sha256_bytes,
    sha256_file,
    verify_hash,
)


def _records(n=50):
    return [
        {"sample_id": i, "label": i % 10, "pixel_sha256": sha256_bytes(bytes([i]))}
        for i in range(n)
    ]


def test_known_sha256_vector():
    # NIST test vector for "abc"
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_file_hash_matches_bytes_hash(tmp_path):
    data = bytes(range(256)) * 10_000  # > 1 chunk
    path = tmp_path / "blob.bin"
    path.write_bytes(data)
    assert sha256_file(path) == sha256_bytes(data)


def test_dataset_hash_deterministic():
    assert manifest_hash(_records()) == manifest_hash(_records())


def test_hash_changes_when_data_changes():
    base = manifest_hash(_records())
    modified = _records()
    modified[7]["pixel_sha256"] = sha256_bytes(b"tampered")
    assert manifest_hash(modified) != base


def test_hash_changes_when_label_changes():
    base = manifest_hash(_records())
    relabelled = _records()
    relabelled[7]["label"] = 9 if relabelled[7]["label"] != 9 else 0
    assert manifest_hash(relabelled) != base


def test_hash_changes_when_record_removed():
    assert manifest_hash(_records()[:-1]) != manifest_hash(_records())


def test_record_order_does_not_change_hash():
    shuffled = _records()
    random.Random(0).shuffle(shuffled)
    assert manifest_hash(shuffled) == manifest_hash(_records())


def test_key_order_does_not_change_hash():
    reordered = [
        {"pixel_sha256": r["pixel_sha256"], "label": r["label"], "sample_id": r["sample_id"]}
        for r in _records()
    ]
    assert manifest_hash(reordered) == manifest_hash(_records())


def test_duplicate_sample_ids_rejected():
    recs = _records(3) + [{"sample_id": 0, "label": 1, "pixel_sha256": "x"}]
    with pytest.raises(ValueError):
        manifest_hash(recs)


def test_canonical_json_is_compact_and_sorted():
    assert canonical_json({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'


def test_verify_hash_case_insensitive():
    h = sha256_bytes(b"x")
    assert verify_hash(h.upper(), h)
    assert not verify_hash(h, sha256_bytes(b"y"))
