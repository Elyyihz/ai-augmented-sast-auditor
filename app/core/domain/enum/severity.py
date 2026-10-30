from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity tier."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """Detection confidence rating."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AssessmentVerdict(str, Enum):
    """AI augmented determination for static analysis finding."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
