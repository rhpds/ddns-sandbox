"""Parse, validate, and serialize BIND TSIG key files (multiple `key { ... };` blocks)."""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass

KEY_BLOCK_RE = re.compile(
    r'key\s+"((?:[^"\\]|\\.)*)"\s*\{([^}]*)\}\s*;',
    re.MULTILINE | re.DOTALL,
)
INNER_ALG_RE = re.compile(r"algorithm\s+([^;\s]+)\s*;", re.MULTILINE)
INNER_SECRET_RE = re.compile(r'secret\s+"((?:[^"\\]|\\.)*)"\s*;', re.MULTILINE)

ALLOWED_ALGORITHMS = frozenset(
    {
        "hmac-md5",
        "hmac-sha1",
        "hmac-sha224",
        "hmac-sha256",
        "hmac-sha384",
        "hmac-sha512",
    }
)

# TSIG key names are typically DNS names; keep conservative to avoid config injection.
KEY_NAME_RE = re.compile(r"^[a-zA-Z0-9_./-]+$")


@dataclass(frozen=True)
class TsigKey:
    name: str
    algorithm: str
    secret_b64: str


class TsigParseError(ValueError):
    pass


def validate_key_name(name: str) -> None:
    if not name or len(name) > 255:
        raise TsigParseError("invalid key name length")
    if not KEY_NAME_RE.fullmatch(name):
        raise TsigParseError("invalid key name characters")


def validate_secret_b64(secret: str) -> None:
    if not secret:
        raise TsigParseError("empty secret")
    try:
        raw = base64.b64decode(secret, validate=True)
    except Exception as e:
        raise TsigParseError("secret is not valid base64") from e
    if len(raw) < 16:
        raise TsigParseError("decoded secret is too short")
    if len(raw) > 512:
        raise TsigParseError("decoded secret is too long")


def generate_tsig_secret(num_bytes: int = 32) -> str:
    """Return a standard base64 secret suitable for BIND TSIG (cryptographically random)."""
    secret = base64.b64encode(secrets.token_bytes(num_bytes)).decode("ascii")
    validate_secret_b64(secret)
    return secret


def _strip_bind_line(line: str) -> str:
    """Remove BIND `//` comments; `//` inside double-quoted strings is kept (TSIG secrets are base64 and may contain `//`)."""
    out: list[str] = []
    i = 0
    in_string = False
    while i < len(line):
        if not in_string:
            if i + 1 < len(line) and line[i] == "/" and line[i + 1] == "/":
                break
            if line[i] == '"':
                in_string = True
            out.append(line[i])
            i += 1
            continue
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            out.append(line[i])
            out.append(line[i + 1])
            i += 2
            continue
        if c == '"':
            in_string = False
        out.append(c)
        i += 1
    return "".join(out)


def _strip_bind_comments(text: str) -> str:
    return "\n".join(_strip_bind_line(line) for line in text.splitlines())


def parse_keyfile(content: str) -> dict[str, TsigKey]:
    """Parse a BIND key file into name -> TsigKey. Raises TsigParseError on corruption."""
    text = _strip_bind_comments(content).strip()
    if not text:
        return {}

    keys: dict[str, TsigKey] = {}
    for m in KEY_BLOCK_RE.finditer(text):
        name = m.group(1)
        inner = m.group(2)

        am = INNER_ALG_RE.search(inner)
        sm = INNER_SECRET_RE.search(inner)
        if not am or not sm:
            raise TsigParseError(f"incomplete key block for {name!r}")

        algorithm = am.group(1).strip().lower()
        secret = sm.group(1)

        if algorithm not in ALLOWED_ALGORITHMS:
            raise TsigParseError(f"unsupported algorithm: {algorithm}")

        validate_key_name(name)
        validate_secret_b64(secret)

        if name in keys:
            raise TsigParseError(f"duplicate key name: {name!r}")

        keys[name] = TsigKey(name=name, algorithm=algorithm, secret_b64=secret)

    leftover = KEY_BLOCK_RE.sub("", text)
    if re.sub(r"\s+", "", leftover):
        raise TsigParseError("unparsed content in key file (possible corruption)")

    return keys


def serialize_keyfile(keys: list[TsigKey]) -> str:
    """Serialize keys in stable sorted order (by name)."""
    if not keys:
        return ""
    lines: list[str] = []
    for k in sorted(keys, key=lambda x: x.name):
        lines.append(f'key "{k.name}" {{')
        lines.append(f"\talgorithm {k.algorithm};")
        lines.append(f'\tsecret "{k.secret_b64}";')
        lines.append("};")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def verify_roundtrip(keys: dict[str, TsigKey]) -> None:
    """Ensure serialization re-parses to the same logical keys."""
    text = serialize_keyfile(list(keys.values()))
    again = parse_keyfile(text)
    if again != keys:
        raise TsigParseError("internal verify failed after serialize")
