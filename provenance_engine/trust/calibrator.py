"""
ConfidenceCalibrator: Platt Scaling and Isotonic Calibration Engine
Transforms raw heuristic and LLM entailment scores into calibrated posterior probabilities.
"""

from enum import Enum
import math
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from config.settings import settings


class CalibrationMethod(str, Enum):
    PLATT_SCALING = "platt_scaling"
    ISOTONIC_STEP = "isotonic_step"


class ConfidenceCalibrator:
    """Calibrates confidence scores using learned sigmoid parameters and Sybil penalty."""

    # Default calibrated Platt parameters
    DEFAULT_PLATT_A = 2.8
    DEFAULT_PLATT_B = -1.4

    @classmethod
    def platt_scale(
        cls,
        raw_score: float,
        a: float = DEFAULT_PLATT_A,
        b: float = DEFAULT_PLATT_B,
    ) -> float:
        """Computes logistic sigmoid mapping: 1 / (1 + exp(-(a * s + b)))."""
        logit = (a * raw_score) + b
        # Bound logit to avoid overflow
        logit = max(-15.0, min(15.0, logit))
        prob = 1.0 / (1.0 + math.exp(-logit))
        return max(0.0, min(1.0, prob))

    @classmethod
    def isotonic_step(cls, raw_score: float) -> float:
        """Piecewise monotonic step calibration."""
        if raw_score < 0.2:
            return 0.05
        elif raw_score < 0.4:
            return 0.25
        elif raw_score < 0.6:
            return 0.50
        elif raw_score < 0.8:
            return 0.75
        elif raw_score < 0.95:
            return 0.90
        return 0.98

    @classmethod
    def calibrate_claim_confidence(
        cls,
        raw_entailment_score: float,
        is_offset_grounded: bool,
        independent_cluster_count: int = 1,
        method: CalibrationMethod = CalibrationMethod.PLATT_SCALING,
    ) -> float:
        """Computes final calibrated confidence combining entailment, exact grounding, and Sybil independence."""
        if not is_offset_grounded:
            # Unanchored quotes are penalized severely
            return 0.05

        if method == CalibrationMethod.PLATT_SCALING:
            base_prob = cls.platt_scale(raw_entailment_score)
        else:
            base_prob = cls.isotonic_step(raw_entailment_score)

        # Multi-source independence multiplier (Sybil penalty)
        # 1 cluster = 0.85 multiplier, 2 clusters = 0.95, >= 3 clusters = 1.0
        if independent_cluster_count <= 1:
            multiplier = 0.85
        elif independent_cluster_count == 2:
            multiplier = 0.95
        else:
            multiplier = 1.0

        calibrated = base_prob * multiplier
        return round(max(0.0, min(1.0, calibrated)), 4)
