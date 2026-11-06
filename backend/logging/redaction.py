"""Keep identity secrets out of every log, at every level (Lab 5).

At ``LOG_LEVEL=DEBUG`` the HTTP clients log what they send and receive.
urllib3 writes each request line with its query string, and duo_universal
sends the token exchange's one-time Duo code and its ``client_assertion`` (a
JWT signed with ``DUO_CLIENT_SECRET``) as query parameters. httpcore writes
response headers, ``Set-Cookie`` included. ``install()`` passes every record
from those loggers through ``redact()`` when the record is created, before
any filter, handler or formatter sees it.

Why a record factory and not a filter on the ``urllib3`` logger: a logger's
filters only see records logged on that logger itself. urllib3 logs the
request line on ``urllib3.connectionpool``, and that record goes to the root
handlers without ever passing the ``urllib3`` logger's filters, so a filter
there would see nothing. The factory covers each logger's whole hierarchy,
including child loggers created later, whatever handlers are configured
(uvicorn's dictConfig, an OTel log handler).

``REDACTED_LOGGERS`` (the HTTP clients, the Duo SDK and the identity modules)
get the full treatment, in the message, its arguments, a traceback and the
stack info:

- every query-string value (``?k=v&k2=v2`` -> ``?k=[REDACTED]&k2=[REDACTED]``);
- sensitive pairs anywhere (``client_secret``, ``client_assertion``, ``code``,
  ``duo_code``, ``id_token``, ``access_token``, ``refresh_token``, ``password``,
  ...), as ``k=v`` or ``"k": "v"``;
- ``Authorization``, ``Proxy-Authorization``, ``Cookie`` and ``Set-Cookie``
  values (httpcore's header tuples, a dict, or a ``Name: value`` line) and
  Bearer / Basic credentials;
- anything shaped like a JWT;
- the identity secrets' exact values (below).

Every OTHER logger's records lose only those exact values: the configured
``DUO_CLIENT_SECRET``, ``DUO_ADMIN_SKEY`` and ``CII_CLIENT_SECRET``, and the
values registered at run time with ``register()`` (the Duo code being
exchanged, the CII access token, an identity cookie). That is done argument
by argument, so a formatter that reads ``record.args`` (uvicorn's access log)
keeps working. Redaction never raises into the code that logs.
"""
from __future__ import annotations

import logging
import re
import threading
import urllib.parse
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any, Optional, Pattern, Tuple

REDACTED = "[REDACTED]"

#: Loggers whose records are fully redacted, each with its whole hierarchy.
REDACTED_LOGGERS: Tuple[str, ...] = (
    "urllib3", "requests", "httpx", "httpcore", "duo_universal",
    # HTTP/2, should httpx ever get http2=True: hpack logs every header at DEBUG.
    "h2", "hpack",
    "backend.services.identity_signin", "backend.services.identity_lookup",
    "backend.services.identity_store", "backend.routers.identity_auth",
    "backend.middleware.identity", "backend.logging.identity_audit",
    "backend.agents.nodes.identity",
)
#: ``settings`` attributes holding identity secrets (.env only).
SECRET_SETTINGS: Tuple[str, ...] = ("duo_client_secret", "duo_admin_skey", "cii_client_secret")

_MIN_SECRET_LEN = 8          # shorter values would match ordinary text
_REGISTERED_MAX = 512        # run-time secrets kept, most recent first out last

_KEYS = (r"client_secret|client_assertion|duo_code|code|id_token|access_token|refresh_token"
         r"|password|passwd|skey|secret|token|api_key|apikey")
_HEADERS = r"authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token"

_PATTERNS: Tuple[Tuple[Pattern[str], str], ...] = (
    # Every value of a query string: keys stay, values go.
    (re.compile(r"([?&])([^=&#\s\"'<>?]+)=([^&#\s\"'<>]*)"), r"\1\2=" + REDACTED),
    # httpcore's header tuples: (b'Set-Cookie', b'...'), ('authorization', '...').
    (re.compile(r"(?i)(b?'(?:" + _HEADERS + r")'\s*,\s*b?')(?:\\.|[^'\\])*'"), r"\1" + REDACTED + "'"),
    (re.compile(r'(?i)(b?"(?:' + _HEADERS + r')"\s*,\s*b?")(?:\\.|[^"\\])*"'), r"\1" + REDACTED + '"'),
    # A dict or JSON: 'Cookie': '...', "access_token": "...".
    (re.compile(r"(?i)('(?:" + _HEADERS + "|" + _KEYS + r")'\s*:\s*b?')(?:\\.|[^'\\])*'"), r"\1" + REDACTED + "'"),
    (re.compile(r'(?i)("(?:' + _HEADERS + "|" + _KEYS + r')"\s*:\s*b?")(?:\\.|[^"\\])*"'), r"\1" + REDACTED + '"'),
    # A header line: "Set-Cookie: ...".
    (re.compile(r"(?im)^(\s*(?:" + _HEADERS + r")\s*:\s*)\S.*$"), r"\1" + REDACTED),
    # A form or free-text pair: client_secret=..., code=... (not status_code=).
    (re.compile(r"(?i)(?<![A-Za-z0-9_.-])(" + _KEYS + r")=(?!\[REDACTED\])([^&\s\"'<>,;)\]}]+)"),
     r"\1=" + REDACTED),
    # Credentials and JWTs anywhere.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 " + REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"), REDACTED),
)

_lock = threading.Lock()
_registered: "OrderedDict[str, None]" = OrderedDict()
_generation = 0
_exact_cache: Tuple[Any, Optional[Pattern[str]]] = (None, None)
_full_names: Tuple[str, ...] = REDACTED_LOGGERS
_full_prefixes: Tuple[str, ...] = tuple(n + "." for n in REDACTED_LOGGERS)
_formatter = logging.Formatter()


# --------------------------------------------------------------------------- secrets
def register(value: Any) -> None:
    """Treat ``value`` (and its URL-encoded form) as a secret in every log from
    now on. Bounded: the most recent ``_REGISTERED_MAX`` values are kept."""
    global _generation
    if not isinstance(value, str) or len(value) < _MIN_SECRET_LEN:
        return
    with _lock:
        for v in {value, urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)}:
            _registered.pop(v, None)
            _registered[v] = None
        while len(_registered) > _REGISTERED_MAX:
            _registered.popitem(last=False)
        _generation += 1


def forget_registered() -> None:
    """Forget the run-time secrets (tests)."""
    global _generation
    with _lock:
        _registered.clear()
        _generation += 1


def _configured_secrets() -> Tuple[str, ...]:
    try:
        from backend.config import settings
    except Exception:  # noqa: BLE001 - logging must work before (and without) the app config
        return ()
    out = []
    for name in SECRET_SETTINGS:
        value = str(getattr(settings, name, "") or "").strip()
        if len(value) >= _MIN_SECRET_LEN:
            out.extend({value, urllib.parse.quote(value, safe="")})
    return tuple(out)


def _exact_pattern() -> Optional[Pattern[str]]:
    """One regex for every exact secret value, rebuilt only when they change."""
    global _exact_cache
    configured = _configured_secrets()
    with _lock:
        key = (configured, _generation)
        if _exact_cache[0] == key:
            return _exact_cache[1]
        values = set(configured) | set(_registered)
    pattern = (re.compile("|".join(re.escape(v) for v in sorted(values, key=len, reverse=True)))
               if values else None)
    with _lock:
        _exact_cache = (key, pattern)
    return pattern


# --------------------------------------------------------------------------- text
def redact_exact(text: str) -> str:
    """``text`` without the identity secrets' exact values."""
    pattern = _exact_pattern()
    return pattern.sub(REDACTED, text) if pattern is not None and text else text


def redact(text: str) -> str:
    """``text`` with every identity secret, code, assertion, cookie and token
    pattern replaced by ``[REDACTED]`` (see the module docstring)."""
    if not text:
        return text
    text = redact_exact(text)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# --------------------------------------------------------------------------- records
def is_redacted_logger(name: str) -> bool:
    """True for a logger in (or under) ``REDACTED_LOGGERS``."""
    return name in _full_names or name.startswith(_full_prefixes)


def _scrub_exception(record: logging.LogRecord, clean: Any) -> None:
    if record.exc_info:
        text = _formatter.formatException(record.exc_info)
        cleaned = clean(text)
        if cleaned != text:
            # The traceback is kept as redacted text; the exception object is
            # dropped so no handler can format the original again.
            record.exc_info, record.exc_text = None, cleaned
    elif record.exc_text:
        record.exc_text = clean(record.exc_text)
    if record.stack_info:
        record.stack_info = clean(record.stack_info)


def redact_record(record: logging.LogRecord) -> logging.LogRecord:
    """Redact one record in place (and return it). Never raises."""
    try:
        if is_redacted_logger(record.name):
            try:
                message = record.getMessage()
            except Exception:  # noqa: BLE001 - a bad format string still must not leak its arguments
                message = f"{record.msg!s} {record.args!r}"
                record.msg, record.args = redact(message), None
            else:
                cleaned = redact(message)
                if cleaned != message:
                    record.msg, record.args = cleaned, None
            _scrub_exception(record, redact)
            return record
        if _exact_pattern() is None:
            return record
        if isinstance(record.msg, str):
            record.msg = redact_exact(record.msg)
        args = record.args
        if isinstance(args, tuple):
            record.args = tuple(redact_exact(a) if isinstance(a, str) else a for a in args)
        elif isinstance(args, Mapping):
            record.args = {k: redact_exact(v) if isinstance(v, str) else v for k, v in args.items()}
        _scrub_exception(record, redact_exact)
    except Exception:  # noqa: BLE001 - redaction never breaks logging
        pass
    return record


def install() -> None:
    """Redact every log record as it is created (idempotent). ``setup_logging``
    calls this before anything is configured."""
    with _lock:
        if installed():
            return
        previous = logging.getLogRecordFactory()

        def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            return redact_record(previous(*args, **kwargs))

        factory._pseudoco_assistant_redaction = True  # type: ignore[attr-defined]
        factory._pseudoco_assistant_previous = previous  # type: ignore[attr-defined]
        logging.setLogRecordFactory(factory)


def installed() -> bool:
    """Whether the redacting record factory is the current one."""
    return bool(getattr(logging.getLogRecordFactory(), "_pseudoco_assistant_redaction", False))
