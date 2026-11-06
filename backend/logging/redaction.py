"""Keep identity secrets out of every log, at every level (Lab 5).

At ``LOG_LEVEL=DEBUG`` the HTTP clients log what they send and receive.
urllib3 writes each request line with its query string, and duo_universal
sends the token exchange's one-time Duo code and its ``client_assertion`` (a
JWT signed with ``DUO_CLIENT_SECRET``) as query parameters. httpcore writes
response headers, ``Set-Cookie`` included. ``install()`` passes every record
through ``redact_record()`` when the record is created, before any filter,
handler or formatter sees it.

Why a record factory and not a filter on the ``urllib3`` logger: a logger's
filters only see records logged on that logger itself. urllib3 logs the
request line on ``urllib3.connectionpool``, and that record goes to the root
handlers without ever passing the ``urllib3`` logger's filters, so a filter
there would see nothing. The factory covers each logger's whole hierarchy,
including child loggers created later, whatever handlers are configured
(uvicorn's dictConfig, an OTel log handler).

**By pattern, never by registration.** What is redacted depends only on the
text of the record and on a fixed set of configured secrets. Nothing a
request, a Duo answer or a cookie carries is ever remembered as a secret, so
no input can make a string (a username, say) disappear from later log lines,
and nothing here grows with traffic.

Every logger's records lose:

- the values of the credential query parameters in ``SENSITIVE_PARAMS``
  (``duo_code``, ``code``, ``state``, ``client_assertion``, ``assertion``,
  ``access_token``, ...): ``?code=x&a=1`` -> ``?code=[REDACTED]&a=1``;
- the values of the headers in ``SENSITIVE_HEADERS`` (``Authorization``,
  ``Cookie``, ``Set-Cookie``, ``X-Access-Key``, ...), as a header line, a
  dict or JSON entry, or httpcore's header tuples, and a ``Bearer``
  credential anywhere;
- the value of a ``name=value`` pair of one of this app's cookies
  (``APP_COOKIES``);
- anything shaped like a JWT;
- the configured secrets' exact values (below).

``REDACTED_LOGGERS`` (the HTTP clients, the Duo SDK and the identity modules)
also lose every query-string value (``?k=v&k2=v2`` ->
``?k=[REDACTED]&k2=[REDACTED]``), sensitive pairs anywhere (``code=...``,
``"token": "..."``, ``password=...``) and ``Basic`` credentials.

The formatted message (with its arguments), a traceback and the stack info
are redacted; a record that changed is kept as its redacted text. The one
exception is a logger whose formatter reads ``record.args`` itself
(``_ARGS_KEPT``: uvicorn's access log unpacks five of them): each argument is
redacted in place, which is complete there because its format string is fixed
and carries nothing.

The configured secrets are the ``SECRET_SETTINGS``: ``DUO_CLIENT_SECRET``,
``DUO_ADMIN_SKEY``, ``CII_CLIENT_SECRET`` and ``ACCESS_KEY``, each when set
and at least 8 characters long (a shorter value would match ordinary text),
as written and URL-encoded. They are compiled into one pattern at
``install()`` (startup) and again only when one of those settings changes:
each record compares the four values with the ones the pattern was built
from. That is the only cache, and it holds one pattern.

Safe inside logging: the record factory takes no lock (a log call made while
redacting, or while ``install()`` holds its lock, cannot deadlock), compiles
nothing per record, and never raises into the code that logs. Every pattern
runs in linear time (no nested quantifier over the same characters).
"""
from __future__ import annotations

import logging
import re
import sys
import threading
import urllib.parse
from collections.abc import Mapping
from typing import Any, Callable, Optional, Pattern, Sequence, Tuple

REDACTED = "[REDACTED]"

#: Loggers whose records get the full treatment, each with its whole hierarchy.
REDACTED_LOGGERS: Tuple[str, ...] = (
    "urllib3", "requests", "httpx", "httpcore", "duo_universal",
    # HTTP/2, should httpx ever get http2=True: hpack logs every header at DEBUG.
    "h2", "hpack",
    "backend.services.identity_signin", "backend.services.identity_lookup",
    "backend.services.identity_store", "backend.routers.identity_auth",
    "backend.middleware.identity", "backend.logging.identity_audit",
    "backend.agents.nodes.identity",
)
#: ``settings`` attributes whose exact values no log record keeps (.env only).
SECRET_SETTINGS: Tuple[str, ...] = ("duo_client_secret", "duo_admin_skey", "cii_client_secret", "access_key")
#: Query parameters whose values are credentials, in every logger's records.
SENSITIVE_PARAMS: Tuple[str, ...] = (
    "duo_code", "code", "state", "client_assertion", "assertion",
    "access_token", "id_token", "refresh_token", "client_secret",
)
#: Headers whose values are credentials, in every logger's records.
SENSITIVE_HEADERS: Tuple[str, ...] = (
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-access-key", "x-api-key", "x-auth-token",
)
#: This app's cookies: middleware.access_key, middleware.settings_gate,
#: middleware.identity and routers.identity_auth (tests/test_duo_signin.py
#: pins the list to them).
APP_COOKIES: Tuple[str, ...] = (
    "md_access", "md_settings", "__Host-pseudoco_assistant_identity",
    "__Secure-pseudoco_assistant_duo_state",
)
#: Loggers whose formatter unpacks ``record.args`` itself: redacted argument
#: by argument, never turned into text.
_ARGS_KEPT = frozenset({"uvicorn.access"})

_MIN_SECRET_LEN = 8          # shorter values would match ordinary text

Rules = Tuple[Tuple[Pattern[str], str], ...]


def _alt(names: Sequence[str]) -> str:
    return "|".join(re.escape(n) for n in names)


_PARAMS = _alt(SENSITIVE_PARAMS)
_HEADERS = _alt(SENSITIVE_HEADERS)
_COOKIES = _alt(APP_COOKIES)
# Keys whose quoted value is a credential in a dict or JSON, in every logger.
_CREDENTIAL_KEYS = _alt(SENSITIVE_HEADERS + APP_COOKIES + (
    "access_token", "id_token", "refresh_token", "client_secret", "client_assertion", "duo_code", "password"))
# The full treatment's sensitive pair keys (REDACTED_LOGGERS only: in other
# loggers "code=" or "state=" can be ordinary text).
_KEYS = (r"client_secret|client_assertion|assertion|duo_code|code|state|id_token|access_token"
         r"|refresh_token|password|passwd|skey|secret|token|api_key|apikey")


def _quoted_value(prefix: str) -> Tuple[Tuple[Pattern[str], str], ...]:
    """``<prefix>'value'`` and ``<prefix>"value"``: the value goes, its quotes stay.
    ``prefix`` holds one ``{q}`` per quote around the key."""
    return tuple(
        (re.compile("(?i)(" + prefix.format(q=q) + ")(?:\\\\.|[^" + q + "\\\\])*" + q), r"\1" + REDACTED + q)
        for q in ("'", '"'))


_COMMON: Rules = (
    # A credential query parameter: ?code=x&state=y -> ?code=[REDACTED]&state=[REDACTED].
    (re.compile(r"(?i)([?&](?:" + _PARAMS + r"))=[^&#\s\"'<>]*"), r"\1=" + REDACTED),
    # httpcore's / hpack's header tuples: (b'Set-Cookie', b'...'), ('authorization', '...').
    *_quoted_value(r"b?{q}(?:" + _HEADERS + r"){q}\s*,\s*b?{q}"),
    # A dict or JSON entry: 'Cookie': '...', "access_token": "...".
    *_quoted_value(r"{q}(?:" + _CREDENTIAL_KEYS + r"){q}\s*:\s*b?{q}"),
    # A header line: "Set-Cookie: ..." ([ \t], never \s: linear on blank lines).
    (re.compile(r"(?im)^([ \t]*(?:" + _HEADERS + r")[ \t]*:[ \t]*)\S.*$"), r"\1" + REDACTED),
    # One of this app's cookies as name=value (a raw Cookie header, a cookie jar).
    (re.compile(r"(?i)(?<![A-Za-z0-9_-])(" + _COOKIES + r")=[^;,\s\"'&]+"), r"\1=" + REDACTED),
    # A Bearer credential anywhere.
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # Anything shaped like a JWT.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"), REDACTED),
)

_FULL: Rules = (
    # Every value of a query string: keys stay, values go.
    (re.compile(r"([?&])([^=&#\s\"'<>?]+)=([^&#\s\"'<>]*)"), r"\1\2=" + REDACTED),
    *_COMMON,
    # A dict or JSON entry of any sensitive key: 'token': '...', "code": "...".
    *_quoted_value(r"{q}(?:" + _KEYS + r"){q}\s*:\s*b?{q}"),
    # A form or free-text pair: client_secret=..., code=... (not status_code=).
    (re.compile(r"(?i)(?<![A-Za-z0-9_.-])(" + _KEYS + r")=(?!\[REDACTED\])([^&\s\"'<>,;)\]}]+)"),
     r"\1=" + REDACTED),
    # Basic (and Bearer) credentials.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 " + REDACTED),
)

_install_lock = threading.RLock()
_formatter = logging.Formatter()


# --------------------------------------------------------------------------- configured secrets
def _configured_values() -> Tuple[str, ...]:
    """The ``SECRET_SETTINGS`` values as they are now. Reads the settings of an
    already imported ``backend.config`` and never imports it: a record can be
    made before it exists, or while it is being imported."""
    module = sys.modules.get("backend.config")
    settings = getattr(module, "settings", None) if module is not None else None
    if settings is None:
        return ()
    return tuple(str(getattr(settings, name, "") or "") for name in SECRET_SETTINGS)


def _compile_secrets(values: Sequence[str]) -> Optional[Pattern[str]]:
    """One pattern for the configured secrets: each long enough to be
    unmistakable, as written and URL-encoded (at most 3 forms of each)."""
    forms = set()
    for raw in values:
        value = raw.strip()
        if len(value) < _MIN_SECRET_LEN or value in REDACTED:
            continue
        forms.update({value, urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)})
    if not forms:
        return None
    return re.compile("|".join(re.escape(v) for v in sorted(forms, key=len, reverse=True)))


# (the values the pattern was built from, the pattern): swapped as one tuple,
# so a reader never sees a half-made pair and no lock is needed.
_secrets: Tuple[Tuple[str, ...], Optional[Pattern[str]]] = ((), None)


def secrets_pattern() -> Optional[Pattern[str]]:
    """The configured secrets' pattern, compiled again only when one of the
    ``SECRET_SETTINGS`` changed since it was built (``None``: none is set)."""
    global _secrets
    values = _configured_values()
    built, pattern = _secrets
    if values != built:
        pattern = _compile_secrets(values)
        _secrets = (values, pattern)
    return pattern


# --------------------------------------------------------------------------- text
def _apply(text: str, rules: Rules, secrets: Optional[Pattern[str]]) -> str:
    if not text:
        return text
    if secrets is not None:
        text = secrets.sub(REDACTED, text)
    for pattern, replacement in rules:
        text = pattern.sub(replacement, text)
    return text


def redact(text: str) -> str:
    """``text`` as a ``REDACTED_LOGGERS`` record keeps it: every query value,
    sensitive pair, credential header, Bearer / Basic credential, JWT and
    configured secret replaced by ``[REDACTED]``."""
    return _apply(text, _FULL, secrets_pattern())


def redact_common(text: str) -> str:
    """``text`` as every other logger's record keeps it: credential query
    parameters, credential headers, this app's cookies, Bearer credentials,
    JWTs and the configured secrets replaced by ``[REDACTED]``."""
    return _apply(text, _COMMON, secrets_pattern())


# --------------------------------------------------------------------------- records
def is_redacted_logger(name: str) -> bool:
    """True for a logger in (or under) ``REDACTED_LOGGERS``."""
    return name in REDACTED_LOGGERS or name.startswith(_FULL_PREFIXES)


_FULL_PREFIXES: Tuple[str, ...] = tuple(n + "." for n in REDACTED_LOGGERS)


def _scrub_exception(record: logging.LogRecord, clean: Callable[[str], str]) -> None:
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


def _redact_message(record: logging.LogRecord, clean: Callable[[str], str]) -> None:
    """Redact the formatted message; a record that changed keeps its redacted
    text (``args`` None), so nothing can sit across the format and an argument."""
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 - a bad format string still must not leak its arguments
        record.msg, record.args = clean(f"{record.msg!s} {record.args!r}"), None
        return
    cleaned = clean(message)
    if cleaned != message:
        record.msg, record.args = cleaned, None


def _redact_args(record: logging.LogRecord, clean: Callable[[str], str]) -> None:
    """Redact each string argument in place (``_ARGS_KEPT``), or the message
    itself when it has none."""
    args = record.args
    if isinstance(args, tuple) and args:
        record.args = tuple(clean(a) if isinstance(a, str) else a for a in args)
    elif isinstance(args, Mapping) and args:
        record.args = {k: clean(v) if isinstance(v, str) else v for k, v in args.items()}
    elif isinstance(record.msg, str):
        record.msg = clean(record.msg)


def redact_record(record: logging.LogRecord) -> logging.LogRecord:
    """Redact one record in place (and return it). Takes no lock, never raises."""
    try:
        secrets = secrets_pattern()
        rules = _FULL if is_redacted_logger(record.name) else _COMMON

        def clean(text: str) -> str:
            return _apply(text, rules, secrets)

        if record.name in _ARGS_KEPT:
            _redact_args(record, clean)
        else:
            _redact_message(record, clean)
        _scrub_exception(record, clean)
    except Exception:  # noqa: BLE001 - redaction never breaks logging
        pass
    return record


def install() -> None:
    """Redact every log record as it is created (idempotent), and compile the
    configured secrets now. ``setup_logging`` calls this before anything is
    configured. The lock is re-entrant and the factory never takes it."""
    with _install_lock:
        secrets_pattern()
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
