"""Request-body cap for the chat POST routes (docs/attachments.md).

A chat turn can carry a base64 PDF in its JSON body, so those two routes get a
hard ceiling: the largest allowed file, base64-encoded, plus headroom for the
envelope (``attachments.max_request_body_bytes()``). Every other route is
untouched.

Pure ASGI rather than ``BaseHTTPMiddleware``, because it has to see the body as
it arrives instead of after it has been read whole:

- a declared ``Content-Length`` over the limit is answered 413 at once, before
  a byte of the body is read;
- a body without one (chunked) is counted as the route reads it, and the read
  that crosses the limit raises ``fastapi.HTTPException(413)``. It has to be
  FastAPI's HTTPException: FastAPI turns any other exception raised while it
  reads a body into a 400 "There was an error parsing the body"
  (fastapi/routing.py), and re-raises only HTTPException as is.

The limit is computed per request, so a test that lowers
``settings.attachment_max_bytes`` takes effect at once. Registered inside the
access-key gate (backend/main.py), so an unauthenticated caller still gets its
401 first.
"""
from __future__ import annotations

import json
from typing import Optional

from fastapi import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.services import attachments

#: The routes whose JSON body may carry an attachment.
LIMITED_PATHS = frozenset({"/api/chat/message", "/api/chat/message/stream"})


def too_large_detail(limit: int) -> str:
    """The 413 detail: a plain string, like every other chat error."""
    mb = f"{limit / (1024 * 1024):.1f}".rstrip("0").rstrip(".")
    return f"Request body too large (limit {mb} MB)"


def _declared_length(scope: Scope) -> Optional[int]:
    for name, value in scope.get("headers") or ():
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None  # malformed: the server rejects it; the count still applies
    return None


class ChatBodyLimitMiddleware:
    """413 for an oversized POST to ``/api/chat/message[/stream]``."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (scope["type"] != "http" or scope.get("method") != "POST"
                or scope.get("path") not in LIMITED_PATHS):
            await self.app(scope, receive, send)
            return

        limit = attachments.max_request_body_bytes()
        declared = _declared_length(scope)
        if declared is not None and declared > limit:
            body = json.dumps({"detail": too_large_detail(limit)}).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii"))],
            })
            await send({"type": "http.response.body", "body": body})
            return

        received = 0

        async def counted_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body") or b"")
                if received > limit:
                    raise HTTPException(status_code=413, detail=too_large_detail(limit))
            return message

        await self.app(scope, counted_receive, send)
