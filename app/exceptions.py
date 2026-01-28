"""Custom exceptions for TechScan application.

Provides structured error handling with categorized exceptions
and standardized error response format.
"""

from typing import Optional, Dict, Any


class TechScanException(Exception):
    """Base exception for all TechScan errors.

    Provides structured error response format with:
    - error_code: Machine-readable error identifier
    - message: Human-readable error description
    - details: Optional additional context
    """

    error_code: str = "TECHSCAN_ERROR"
    status_code: int = 500

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Return structured error response dict."""
        response = {
            "error": True,
            "error_code": self.error_code,
            "message": self.message,
        }
        if self.details:
            response["details"] = self.details
        return response


# ============ Validation Errors (4xx) ============


class ValidationError(TechScanException):
    """Input validation failed."""

    error_code = "VALIDATION_ERROR"
    status_code = 400


class InvalidDomainError(ValidationError):
    """Invalid domain format or blocked domain."""

    error_code = "INVALID_DOMAIN"

    def __init__(self, domain: str, reason: str = "Invalid domain format"):
        super().__init__(f"{reason}: {domain}", details={"domain": domain, "reason": reason})


class SSRFBlockedError(ValidationError):
    """Domain blocked due to SSRF protection."""

    error_code = "SSRF_BLOCKED"
    status_code = 403

    def __init__(self, domain: str):
        super().__init__(
            f"Domain appears to be internal/private: {domain}", details={"domain": domain, "reason": "SSRF protection"}
        )


class RateLimitExceededError(TechScanException):
    """Rate limit exceeded."""

    error_code = "RATE_LIMIT_EXCEEDED"
    status_code = 429

    def __init__(self, limit: str = "unknown", retry_after: Optional[int] = None):
        details = {"limit": limit}
        if retry_after:
            details["retry_after_seconds"] = retry_after
        super().__init__(f"Rate limit exceeded: {limit}", details=details)


# ============ Authentication Errors ============


class AuthenticationError(TechScanException):
    """Authentication failed."""

    error_code = "AUTHENTICATION_ERROR"
    status_code = 401


class UnauthorizedError(AuthenticationError):
    """Missing or invalid authentication token."""

    error_code = "UNAUTHORIZED"

    def __init__(self, hint: str = "Set X-Admin-Token header"):
        super().__init__("Unauthorized access", details={"hint": hint})


# ============ Scan Errors ============


class ScanError(TechScanException):
    """Base class for scan-related errors."""

    error_code = "SCAN_ERROR"


class ScanTimeoutError(ScanError):
    """Scan operation timed out."""

    error_code = "SCAN_TIMEOUT"
    status_code = 504

    def __init__(self, domain: str, timeout_seconds: int):
        super().__init__(
            f"Scan timed out for {domain} after {timeout_seconds}s",
            details={"domain": domain, "timeout_seconds": timeout_seconds},
        )


class ScanFailedError(ScanError):
    """Scan operation failed."""

    error_code = "SCAN_FAILED"

    def __init__(self, domain: str, reason: str):
        super().__init__(f"Scan failed for {domain}: {reason}", details={"domain": domain, "reason": reason})


class DomainUnreachableError(ScanError):
    """Domain is unreachable."""

    error_code = "DOMAIN_UNREACHABLE"
    status_code = 502

    def __init__(self, domain: str, reason: str = "Connection failed"):
        super().__init__(f"Cannot reach {domain}: {reason}", details={"domain": domain, "reason": reason})


# ============ Database Errors ============


class DatabaseError(TechScanException):
    """Database operation failed."""

    error_code = "DATABASE_ERROR"
    status_code = 503


# ============ Configuration Errors ============


class ConfigurationError(TechScanException):
    """Configuration issue."""

    error_code = "CONFIGURATION_ERROR"

    def __init__(self, setting: str, message: str):
        super().__init__(f"Configuration error for {setting}: {message}", details={"setting": setting})


# ============ Utility Functions ============


def error_response(exception: TechScanException) -> tuple:
    """Create Flask JSON response from exception.

    Returns:
        Tuple of (response_dict, status_code) ready for jsonify
    """
    return exception.to_dict(), exception.status_code


def make_error_response(
    error_code: str, message: str, status_code: int = 500, details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create structured error response dict without exception.

    Useful for creating error responses directly in routes.
    """
    response = {
        "error": True,
        "error_code": error_code,
        "message": message,
    }
    if details:
        response["details"] = details
    return response
