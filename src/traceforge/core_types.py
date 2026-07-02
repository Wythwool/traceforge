"""Small shared types for TraceForge internals."""


class AnalysisError(ValueError):
    """Raised when a parser recognizes a format but cannot parse it safely."""
