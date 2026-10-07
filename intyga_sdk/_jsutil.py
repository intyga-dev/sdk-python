"""JavaScript-compatible primitives for the offline-approval port (docs/OFFLINE-APPROVAL-SDK.md).

The TypeScript SDK is the reference, and several of its observable outputs are JavaScript built-ins:
``Date#toISOString`` timestamps, ``JSON.stringify`` text, ``String#trim`` and Node's forgiving
``Buffer.from(s, "base64")``. Tools in different languages share one bundle directory and exchange
``DIV1:``/``SIG1:`` envelopes, so these have to agree byte for byte. Private: nothing here is API.
"""

import base64
import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import _parse_rfc3339

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_MS = timedelta(milliseconds=1)
MAX_SAFE_INTEGER = 2**53 - 1

# ECMAScript WhiteSpace + LineTerminator — what String#trim strips. Not Python's str.isspace set:
# that one omits U+FEFF (which JS trims) and includes U+001C..U+001F and U+0085 (which JS keeps).
_JS_WHITESPACE = (
    "\t\n\v\f\r              "
    "    　﻿"
)
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")
_SURROGATE = re.compile("[\ud800-\udfff]")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def epoch_ms(dt: datetime) -> int:
    """Milliseconds since the epoch, exactly, as a JavaScript Date holds time.

    Integer arithmetic on purpose: ``datetime.timestamp()`` is a float, and the vectors pin
    boundaries (a bundle exactly 30 days old is accepted, 30 days and 1 ms is not) that float
    rounding can move. A naive datetime is read as local time, as ``datetime.timestamp()`` and the
    existing verifier read it.
    """
    return (dt.astimezone(timezone.utc) - _EPOCH) // _ONE_MS


def to_iso_string(dt: datetime) -> str:
    """``Date#toISOString``: UTC, exactly three fractional digits, ``Z``. Sub-millisecond precision is
    dropped, as a JavaScript Date has none."""
    return iso_from_ms(epoch_ms(dt))


def iso_from_ms(ms: int) -> str:
    """``new Date(ms).toISOString()``. Formatted by hand because ``strftime("%Y")`` does not zero-pad
    years below 1000 on every platform."""
    d = _EPOCH + timedelta(milliseconds=ms)
    return (
        f"{d.year:04d}-{d.month:02d}-{d.day:02d}T{d.hour:02d}:{d.minute:02d}:{d.second:02d}"
        f".{d.microsecond // 1000:03d}Z"
    )


def timestamp_ms(value: Any) -> Optional[int]:
    """An RFC 3339 timestamp as epoch milliseconds, or None when it is not one.

    Stricter than the reference's ``Date.parse``, which also takes forms such as a bare date: this
    uses the verifier's single RFC 3339 grammar (DIV §6.2). Every timestamp read here was written by
    ``toISOString``, so the difference only ever refuses something malformed.
    """
    parsed = _parse_rfc3339(value)
    return None if parsed is None else epoch_ms(parsed)


def js_trim(s: str) -> str:
    """``String.prototype.trim``: ECMAScript WhiteSpace + LineTerminator — every ``Zs`` space, TAB,
    VT, FF, U+FEFF (a BOM), LF, CR, U+2028, U+2029 — and nothing else (U+0085 stays)."""
    return s.strip(_JS_WHITESPACE)


def b64url_decode_strict(s: str) -> bytes:
    """Strict base64url, padded or not (``[A-Za-z0-9_-]*={0,2}``); raises ``ValueError`` otherwise.

    A character outside the alphabet is refused, never skipped: Node's forgiving decoder skips stray
    characters, so a paste with stray text in it would decode to something other than what was sent,
    and every SDK refuses such input. As in the reference, a dangling final character (a length of
    1 mod 4) carries no whole byte and is dropped.
    """
    if not isinstance(s, str) or _BASE64URL.fullmatch(s) is None:
        raise ValueError("not base64url")
    data = s.rstrip("=")
    if len(data) % 4 == 1:
        data = data[:-1]
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def b64_length(s: str) -> int:
    """How many bytes ``Buffer.from(s, "base64")`` yields, for a string already checked against
    ``^[A-Za-z0-9+/_-]+={0,2}$``: three bytes per four characters, rounded down."""
    return len(s.rstrip("=")) * 3 // 4


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def json_loads(text: Any) -> Any:
    """``JSON.parse``: as ``json.loads``, but refusing NaN/Infinity, which JSON does not have."""
    return json.loads(text, parse_constant=_refuse_constant)


def json_dumps(value: Any, indent: Optional[int] = None) -> str:
    """``JSON.stringify(value)`` / ``JSON.stringify(value, null, indent)`` for JSON data.

    Non-ASCII is emitted raw and a lone surrogate as a lowercase ``\\udxxx`` escape, as JavaScript
    does; ``json.dumps(ensure_ascii=False)`` would emit the raw surrogate, which no UTF-8 encoder can
    write. (A whole-valued float still prints as ``1.0`` where JavaScript prints ``1``; nothing
    written through this is signed.)
    """
    separators = (",", ":") if indent is None else (",", ": ")
    text = json.dumps(value, ensure_ascii=False, allow_nan=False, indent=indent, separators=separators)
    return _SURROGATE.sub(lambda m: "\\u%04x" % ord(m.group()), text)


def is_number(value: Any) -> bool:
    """A JavaScript number: int or float, never bool (``True`` is an ``int`` in Python)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_integer(value: Any) -> bool:
    """``Number.isInteger``. JSON ``2.0`` is the integer 2 in JavaScript, so an integral float counts."""
    if not is_number(value):
        return False
    return isinstance(value, int) or (math.isfinite(value) and float(value).is_integer())


def is_safe_integer(value: Any) -> bool:
    """``Number.isSafeInteger``."""
    return is_integer(value) and abs(value) <= MAX_SAFE_INTEGER


def strict_equal(a: Any, b: Any) -> bool:
    """``a === b`` for JSON scalars. Python's ``==`` says ``True == 1`` and ``None`` differs from
    nothing in a way JavaScript's ``undefined``/``false`` comparison needs; both are handled here."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if is_number(a) and is_number(b):
        return a == b
    if a is None or b is None:
        return a is b
    return type(a) is type(b) and a == b


def truthy(value: Any) -> bool:
    """JavaScript truthiness. Differs from Python's for ``[]`` and ``{}``, which are truthy there."""
    if value is None or value is False:
        return False
    if is_number(value):
        return value != 0 and not (isinstance(value, float) and math.isnan(value))
    if isinstance(value, str):
        return value != ""
    return True
