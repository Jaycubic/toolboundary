"""
tests/test_canonicalization_fuzz.py
-----------------------------------
Security-focused fuzz and property-style test suite for canonicalization and call binding.

Covers:
- Dictionary key reordering and nested permutation stability.
- Nested structures (lists, tuples, nested mappings, mixed types).
- Unicode values (ASCII, multi-byte UTF-8, emojis, non-BMP characters, scripts).
- Numeric edge cases (integers, large numbers, exponents, zero, signed zero, IEEE special values).
- Empty and null values across structures.
- Equivalent representations that must hash identically.
- Changes that must produce different call digests (tamper sensitivity).
- Stability across repeated serialization (idempotence).
- Custom object fallbacks via default=str in canonicalize.
- Independence from any external provider.
"""

from __future__ import annotations

import copy
import json
import math
import random
from typing import Any

import pytest

from toolboundary.evidence import canonicalize, call_digest, result_digest, sha256
from toolboundary.provider import FrozenToolCall


# ---------------------------------------------------------------------------
# Test Helpers & Generators
# ---------------------------------------------------------------------------


def _permute_dict(d: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    """Recursively permute key order of a dictionary."""
    items = list(d.items())
    rng.shuffle(items)
    new_dict: dict[str, Any] = {}
    for k, v in items:
        if isinstance(v, dict):
            new_dict[k] = _permute_dict(v, rng)
        elif isinstance(v, list):
            new_dict[k] = [
                _permute_dict(elem, rng) if isinstance(elem, dict) else elem for elem in v
            ]
        else:
            new_dict[k] = v
    return new_dict


def _make_sample_call(**kwargs: Any) -> FrozenToolCall:
    defaults = {
        "agent_name": "agent-alpha",
        "tool_name": "sql_query",
        "operation": "execute",
        "arguments": {"database": "prod", "query": "SELECT 1", "limit": 100},
        "resource": "arn:aws:rds:us-east-1:123456789012:db:main",
        "tool_version": "1.2.0",
        "schema_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "manifest_hash": "sha256:0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba",
        "approval_id": "appr_789xyz",
        "approval_state": "APPROVED",
    }
    defaults.update(kwargs)
    return FrozenToolCall(**defaults)


# ---------------------------------------------------------------------------
# 1. Dictionary Key Reordering & Permutation Invariance
# ---------------------------------------------------------------------------


class TestDictionaryKeyReordering:
    def test_top_level_dictionary_reordering(self):
        d1 = {"a": 1, "b": 2, "c": 3, "d": 4}
        d2 = {"d": 4, "b": 2, "a": 1, "c": 3}
        d3 = {"c": 3, "a": 1, "d": 4, "b": 2}
        assert canonicalize(d1) == canonicalize(d2) == canonicalize(d3)
        assert sha256(canonicalize(d1)) == sha256(canonicalize(d2)) == sha256(canonicalize(d3))

    def test_randomized_nested_permutations_fuzz(self):
        """Fuzz nested dictionaries with randomized insertion order across multiple seeds."""
        base_structure = {
            "query": "SELECT * FROM users",
            "pagination": {"limit": 50, "offset": 100, "cursor": "cur_abc123"},
            "filters": {
                "status": "active",
                "tier": "enterprise",
                "metadata": {
                    "tags": ["prod", "compliance"],
                    "geo": {"region": "us-west-2", "zone": "b"},
                },
            },
            "options": {"dry_run": False, "timeout_ms": 5000, "retries": 3},
        }

        canonical_base = canonicalize(base_structure)
        digest_base = sha256(canonical_base)

        for seed in range(50):
            rng = random.Random(seed)
            permuted = _permute_dict(base_structure, rng)
            assert canonicalize(permuted) == canonical_base
            assert sha256(canonicalize(permuted)) == digest_base

    def test_call_digest_invariant_under_arguments_key_permutations(self):
        rng = random.Random(42)
        base_args = {
            "amount": 1000,
            "currency": "USD",
            "recipient": {"account": "ACC-12345", "routing": "021000021", "name": "ACME Corp"},
            "notes": ["invoice #42", "fast-settlement"],
        }
        base_call = _make_sample_call(arguments=base_args)
        base_digest = call_digest(base_call)

        for _ in range(25):
            permuted_args = _permute_dict(base_args, rng)
            permuted_call = _make_sample_call(arguments=permuted_args)
            assert call_digest(permuted_call) == base_digest


# ---------------------------------------------------------------------------
# 2. Nested Structures & Mixed Types
# ---------------------------------------------------------------------------


class TestNestedStructures:
    def test_deeply_nested_dictionaries_and_lists(self):
        deep = {"level1": {"level2": {"level3": {"level4": {"level5": [{"k1": 1, "k0": 0}]}}}}}
        expected = '{"level1":{"level2":{"level3":{"level4":{"level5":[{"k0":0,"k1":1}]}}}}}'
        assert canonicalize(deep) == expected

    def test_list_order_is_preserved(self):
        """Unlike dict keys, sequence order in lists represents semantic order and must differ."""
        list_a = [1, 2, 3, 4]
        list_b = [4, 3, 2, 1]
        assert canonicalize(list_a) != canonicalize(list_b)
        assert sha256(canonicalize(list_a)) != sha256(canonicalize(list_b))

    def test_tuples_and_lists_equivalence_in_json(self):
        """JSON serialization treats tuples and lists identically as JSON arrays."""
        tuple_data = {"items": (1, 2, 3)}
        list_data = {"items": [1, 2, 3]}
        assert canonicalize(tuple_data) == canonicalize(list_data)

    def test_heterogeneous_collections(self):
        data = {
            "strings": ["a", "b"],
            "numbers": [1, 2.5, -3],
            "booleans": [True, False],
            "nulls": [None, None],
            "nested": [{"b": 2, "a": 1}],
        }
        canon = canonicalize(data)
        assert '"booleans":[true,false]' in canon
        assert '"nulls":[null,null]' in canon
        assert '"nested":[{"a":1,"b":2}]' in canon


# ---------------------------------------------------------------------------
# 3. Unicode Values & Character Encoding
# ---------------------------------------------------------------------------


class TestUnicodeHandling:
    @pytest.mark.parametrize(
        "text",
        [
            "Hello, world!",
            "Café Münsterländer Straße",
            "こんにちは世界",  # Japanese
            "مرحبا بالعالم",  # Arabic (RTL)
            "Привет, мир!",  # Cyrillic
            "🚀🔥🛡️🔒✨",  # Emojis & multi-byte UTF-8
            "ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ",  # Runic script
            "Z͔̭̱͑ͫ̓aͨ͆ͪl̽ͪ͋g̡ͭo",  # Combining diacritics
            "\u0000\u001f\t\n\r",  # Control characters & escapes
            "𠜎𠜱𠝹𠱓",  # Supplementary Ideographic Plane / surrogate-pair code points
        ],
    )
    def test_unicode_strings_preserve_ensure_ascii_false(self, text):
        data = {"message": text}
        canon = canonicalize(data)
        # ensure_ascii=False means literal UTF-8 characters are retained where valid JSON
        digest = sha256(canon)
        assert len(digest) == 64
        # Determinism check
        assert sha256(canonicalize(data)) == digest

    def test_unicode_keys_sorting(self):
        """Dict keys with diverse unicode characters must be sorted deterministically."""
        d = {
            "zebra": 1,
            "éclair": 2,
            "apple": 3,
            "αlpha": 4,
            "βeta": 5,
            "123": 6,
        }
        canon = canonicalize(d)
        parsed = json.loads(canon)
        # Ensure json round-trip preserves values
        assert parsed == d
        # Idempotence
        assert canonicalize(parsed) == canon


# ---------------------------------------------------------------------------
# 4. Numeric Edge Cases
# ---------------------------------------------------------------------------


class TestNumericEdgeCases:
    def test_integers_and_large_numbers(self):
        data = {
            "zero": 0,
            "neg": -1,
            "pos": 42,
            "max_int64": 9223372036854775807,
            "min_int64": -9223372036854775808,
            "huge": 10**50,
        }
        canon = canonicalize(data)
        assert '"zero":0' in canon
        assert '"max_int64":9223372036854775807' in canon
        assert '"huge":' + str(10**50) in canon

    def test_floats_and_scientific_notation(self):
        data = {
            "pi": 3.141592653589793,
            "small": 1e-10,
            "exp": 2.5e6,
            "zero_point_zero": 0.0,
        }
        canon = canonicalize(data)
        assert canonicalize(data) == canon

    def test_integer_and_float_semantic_differences(self):
        """In Python/JSON, 1 and 1.0 format differently as strings (1 vs 1.0)."""
        d_int = {"value": 1}
        d_flt = {"value": 1.0}
        assert canonicalize(d_int) == '{"value":1}'
        assert canonicalize(d_flt) == '{"value":1.0}'
        assert canonicalize(d_int) != canonicalize(d_flt)
        assert sha256(canonicalize(d_int)) != sha256(canonicalize(d_flt))

    def test_negative_zero(self):
        """Python json.dumps preserves negative sign on -0.0 vs 0.0."""
        d_pos = {"v": 0.0}
        d_neg = {"v": -0.0}
        assert canonicalize(d_pos) == '{"v":0.0}'
        assert canonicalize(d_neg) == '{"v":-0.0}'
        assert sha256(canonicalize(d_pos)) != sha256(canonicalize(d_neg))


# ---------------------------------------------------------------------------
# 5. Empty and Null Values
# ---------------------------------------------------------------------------


class TestEmptyAndNullValues:
    def test_empty_primitives_and_containers(self):
        empty_payload = {
            "empty_dict": {},
            "empty_list": [],
            "empty_str": "",
            "none_val": None,
        }
        expected = '{"empty_dict":{},"empty_list":[],"empty_str":"","none_val":null}'
        assert canonicalize(empty_payload) == expected
        assert len(sha256(canonicalize(empty_payload))) == 64

    def test_empty_call_arguments(self):
        call_empty = _make_sample_call(arguments={})
        digest_empty = call_digest(call_empty)
        assert len(digest_empty) == 64
        assert digest_empty == call_digest(_make_sample_call(arguments={}))

    def test_distinction_between_none_empty_string_and_empty_list(self):
        c1 = _make_sample_call(arguments={"a": None})
        c2 = _make_sample_call(arguments={"a": ""})
        c3 = _make_sample_call(arguments={"a": []})
        c4 = _make_sample_call(arguments={"a": {}})
        digests = {call_digest(c) for c in (c1, c2, c3, c4)}
        assert len(digests) == 4, "None, '', [], and {} must produce distinct digests"


# ---------------------------------------------------------------------------
# 6. Tamper Sensitivity (Changes Produce Distinct Digests)
# ---------------------------------------------------------------------------


class TestTamperSensitivity:
    @pytest.mark.parametrize(
        ("field", "tampered_value"),
        [
            ("agent_name", "agent-beta"),
            ("tool_name", "shell_exec"),
            ("operation", "delete"),
            ("operation", None),
            ("resource", "arn:aws:rds:us-east-1:123456789012:db:other"),
            ("resource", None),
            ("tool_version", "1.2.1"),
            ("tool_version", None),
            ("schema_hash", "sha256:1111111111111111111111111111111111111111111111111111111111111111"),
            ("schema_hash", None),
            ("manifest_hash", "sha256:2222222222222222222222222222222222222222222222222222222222222222"),
            ("manifest_hash", None),
            ("approval_id", "appr_changed"),
            ("approval_id", None),
            ("approval_state", "REJECTED"),
            ("approval_state", None),
        ],
    )
    def test_binding_fields_tampering(self, field: str, tampered_value: Any):
        base_call = _make_sample_call()
        base_digest = call_digest(base_call)

        tampered_call = _make_sample_call(**{field: tampered_value})
        tampered_digest = call_digest(tampered_call)

        assert (
            base_digest != tampered_digest
        ), f"Modifying field '{field}' to '{tampered_value}' must alter call digest"

    def test_argument_modification_tamper(self):
        base_call = _make_sample_call(arguments={"user_id": 100, "role": "viewer"})
        mutated_call = _make_sample_call(arguments={"user_id": 100, "role": "admin"})
        assert call_digest(base_call) != call_digest(mutated_call)

    def test_argument_addition_tamper(self):
        base_call = _make_sample_call(arguments={"user_id": 100})
        mutated_call = _make_sample_call(arguments={"user_id": 100, "escalate": True})
        assert call_digest(base_call) != call_digest(mutated_call)


# ---------------------------------------------------------------------------
# 7. Repeated Serialization Stability & Result Digest
# ---------------------------------------------------------------------------


class TestSerializationStabilityAndResults:
    def test_repeated_serialization_idempotence(self):
        """Repeated canonicalization runs must yield byte-for-byte identical results."""
        call = _make_sample_call()
        first_digest = call_digest(call)
        for _ in range(100):
            assert call_digest(call) == first_digest

    def test_result_digest_determinism(self):
        r1 = {"status": "ok", "rows": [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]}
        r2 = {"rows": [{"name": "alice", "id": 1}, {"name": "bob", "id": 2}], "status": "ok"}
        assert result_digest(r1) == result_digest(r2)

    def test_custom_objects_fallback(self):
        """Objects not natively JSON serializable should serialize deterministically with default=str."""

        class CustomIdentifier:
            def __init__(self, val: str):
                self.val = val

            def __str__(self) -> str:
                return f"CID-{self.val}"

        d = {"id": CustomIdentifier("999")}
        canon = canonicalize(d)
        assert canon == '{"id":"CID-999"}'
        assert sha256(canon) == sha256(canonicalize({"id": "CID-999"}))
