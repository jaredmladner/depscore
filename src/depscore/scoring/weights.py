DEFAULT_DIMENSION_WEIGHTS: dict[str, float] = {
    "security_posture": 0.35,
    "maintainability": 0.30,
    "maturity": 0.20,
    "community_health": 0.15,
}

DEFAULT_BLEND_WEIGHTS: dict[str, float] = {
    "rules": 0.40,
    "ai": 0.60,
}

GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (80.0, "A"),
    (65.0, "B"),
    (50.0, "C"),
    (35.0, "D"),
    (0.0, "F"),
]


def score_to_grade(score: float) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"
