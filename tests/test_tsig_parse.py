"""TSIG keyfile parse/serialize edge cases."""

import base64
import random

from bind_key_api.tsig import TsigKey, parse_keyfile, serialize_keyfile, verify_roundtrip


def test_parse_preserves_double_slash_inside_base64_secret():
    # Base64 may contain "//"; naive "//" comment stripping must not truncate the secret.
    k = TsigKey(
        name="k.example.com",
        algorithm="hmac-sha256",
        secret_b64="3fxb6AS9p9DuxP8wKuM//6cUqr6iGS0bqNIKD9PbDJM=",
    )
    text = serialize_keyfile([k])
    assert "//6cUqr6iGS0bqNIKD9PbDJM=" in text
    parsed = parse_keyfile(text)
    assert parsed["k.example.com"] == k


def test_strip_line_comment_outside_strings():
    # 24-char base64 = 16 bytes decoded (minimum valid secret)
    sec = "AAAAAAAAAAAAAAAAAAAAAA=="
    raw = f'key "a" {{\n\talgorithm hmac-sha256; // algo note\n\tsecret "{sec}";\n}};'
    parsed = parse_keyfile(raw)
    assert parsed["a"].algorithm == "hmac-sha256"
    assert parsed["a"].secret_b64 == sec


def test_verify_roundtrip_many_random_seeds():
    for seed in range(5000):
        random.seed(seed)
        keys = {}
        for i in range(25):
            name = f"parallel-{i:02d}.client.ddns.example.com"
            sec = base64.b64encode(random.randbytes(32)).decode("ascii")
            keys[name] = TsigKey(name=name, algorithm="hmac-sha256", secret_b64=sec)
        verify_roundtrip(keys)
