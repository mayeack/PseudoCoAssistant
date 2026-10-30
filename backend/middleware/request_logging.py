from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import time
import logging
import uuid
from backend.logging.governance_logger import governance_logger

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all HTTP requests"""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        start_time = time.time()

        # Add request ID to request state
        request.state.request_id = request_id
        # The routed path, not request.url.path: request.url is rebuilt from the
        # Host header, so a crafted Host would make the log name the wrong route.
        path = request.scope.get("path") or "/"

        # Log request
        logger.info(
            f"Request started: {request.method} {path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": path,
                "client": request.client.host if request.client else None
            }
        )

        try:
            response = await call_next(request)
            duration = time.time() - start_time

            # Log response
            logger.info(
                f"Request completed: {request.method} {path} - {response.status_code}",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration": duration,
                    "client": request.client.host if request.client else None
                }
            )

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            return response

        except Exception as e:
            duration = time.time() - start_time

            # Log error
            logger.error(
                f"Request failed: {request.method} {path} - {str(e)}",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": path,
                    "error": str(e),
                    "duration": duration,
                    "client": request.client.host if request.client else None
                }
            )

            raise
