"""Flow ingestion pipeline; classification remains owned by the FastAPI service."""

from .feature_adapter import FeatureAdapter, FeatureCompatibilityError

__all__ = ["FeatureAdapter", "FeatureCompatibilityError"]
