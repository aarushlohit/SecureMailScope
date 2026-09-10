"""
SecureMailScope - LLM Provider Exceptions
"""

class LLMException(Exception):
    """Base exception for all LLM errors."""
    pass


class AuthenticationError(LLMException):
    """Raised when API key or authorization fails."""
    pass


class RateLimitError(LLMException):
    """Raised when provider rate limit is exceeded."""
    pass


class TimeoutError(LLMException):
    """Raised when provider call times out."""
    pass


class ProviderUnavailableError(LLMException):
    """Raised when provider endpoint is unreachable or 5xx."""
    pass


class ProviderError(LLMException):
    """Generic provider execution error."""
    pass
