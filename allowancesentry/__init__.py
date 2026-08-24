"""Offline, deterministic EVM allowance exposure analysis."""

from .analyze import AnalysisError, analyze_snapshot

__all__ = ["AnalysisError", "analyze_snapshot"]
__version__ = "0.1.0"
