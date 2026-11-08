"""The errors of the shared getEndUser answer table that carry a code.

Not a suite (tests/run_all.sh does not run it): tests/test_identity_gate.py
(the app's gate, ``identity_lookup._cii_parse``) and
tests/test_identity_personas.py (the Mac's self-check,
``lab5_cii.parse_end_user``) both build the coded errors of
tests/fixtures/cii_end_user_answers.json here, so the two try the same ones.

``coded_errors`` crosses the table's ``coded_errors`` section: each of its
``codes`` in each of its ``places``, alone and then in all of them at once,
on each of its ``messages``, then the ``errors`` it lists (two different codes
on one error). A code the table holds is so tried in every place it covers,
never only where an entry happened to put it. Given ``all_messages`` it puts
them on every message the table holds instead (the code-less
``error_messages`` and the messages of its ``cases`` too), so no code the
table holds and no message it holds go untried together.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Sequence, Tuple


def with_code(error: Dict[str, Any], place: str, code: Any) -> Dict[str, Any]:
    """A copy of ``error`` with ``code`` at ``place``, a dotted path such as
    ``extensions.errorType`` (``errorType`` is on the error itself)."""
    out = copy.deepcopy(error)
    *parents, leaf = place.split(".")
    node = out
    for key in parents:
        node = node.setdefault(key, {})
    node[leaf] = code
    return out


def all_messages(table: Dict[str, Any]) -> List[str]:
    """Every message the table holds, once each: the ``coded_errors``
    section's, the code-less ``error_messages``, then every error message in
    its ``cases`` and listed coded ``errors`` (tests/test_identity_gate.py
    checks this against its own walk of the table)."""
    out: List[str] = []

    def add(message: Any) -> None:
        if isinstance(message, str) and message not in out:
            out.append(message)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            add(node.get("message"))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for message in list(table["coded_errors"]["messages"]) + list(table["error_messages"]["messages"]):
        add(message)
    walk(table["cases"])
    walk(table["coded_errors"]["errors"])
    return out


def coded_errors(table: Dict[str, Any],
                 messages: Optional[Sequence[str]] = None) -> List[Tuple[str, Dict[str, Any]]]:
    """Every error of the table's ``coded_errors``, as ``(name, error)``: each
    code in each place alone and in every place at once, on each message (the
    section's, or ``messages``: ``all_messages`` for every one the table
    holds), then the listed errors. None carries a path: the shape it is tried
    in gives it."""
    section = table["coded_errors"]
    places = list(section["places"])
    out: List[Tuple[str, Dict[str, Any]]] = []
    for where in [[place] for place in places] + [places]:
        label = where[0] if len(where) == 1 else "every place at once"
        for code in section["codes"]:
            for message in (section["messages"] if messages is None else messages):
                error: Dict[str, Any] = {"message": message}
                for place in where:
                    error = with_code(error, place, code)
                out.append((f"{code} in {label}, on {message!r}", error))
    out += [(entry["name"], copy.deepcopy(entry["error"])) for entry in section["errors"]]
    return out
