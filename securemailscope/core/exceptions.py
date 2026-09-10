"""
SecureMailScope - Domain Exceptions
"""


class SecureMailScopeException(Exception):
    """Base exception for SecureMailScope."""
    pass


class InvalidArtifactError(SecureMailScopeException):
    """Raised when an uploaded PCAP or file is invalid or corrupted."""
    pass


class EvidenceValidationError(SecureMailScopeException):
    """Raised when finding validation fails due to invalid or unpersisted evidence."""
    pass


class ToolExecutionError(SecureMailScopeException):
    """Raised when a forensic tool execution fails in the gateway."""
    pass


class HypothesisStateError(SecureMailScopeException):
    """Raised on invalid hypothesis state transitions."""
    pass
