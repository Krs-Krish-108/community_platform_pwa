"""
Unit tests for app.domain.member_service — secure Member ID generation.
Verifies IDs are random and never derived from name/timestamp (FR-IMP-005).
"""
import re

from app.domain.member_service import _generate_candidate_id, _ID_LENGTH, _ID_ALPHABET


def test_generate_candidate_id_correct_length():
    candidate = _generate_candidate_id()
    assert len(candidate) == _ID_LENGTH


def test_generate_candidate_id_uses_only_allowed_alphabet():
    candidate = _generate_candidate_id()
    assert all(c in _ID_ALPHABET for c in candidate)


def test_generate_candidate_id_excludes_ambiguous_characters():
    # 0/O and 1/I are excluded from the alphabet for readability
    assert "0" not in _ID_ALPHABET
    assert "O" not in _ID_ALPHABET
    assert "1" not in _ID_ALPHABET
    assert "I" not in _ID_ALPHABET


def test_generate_candidate_id_is_not_deterministic():
    """
    Two calls must produce different IDs — proving the ID is NOT derived
    from any fixed input like a name or timestamp seed.
    """
    ids = {_generate_candidate_id() for _ in range(50)}
    assert len(ids) == 50  # all unique across 50 generations


def test_generate_candidate_id_is_not_a_reproducible_hash_of_name():
    """
    FR-IMP-005 regression guard: the legacy prototype used makeId(name+timestamp),
    which is reproducible. The secure generator must give different output
    for the same conceptual "seed" across calls.
    """
    a = _generate_candidate_id()
    b = _generate_candidate_id()
    assert a != b
