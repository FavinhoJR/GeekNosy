"""Compatibilidad con datos legacy (notas A-F, estados improved/worsened, modo govscan)."""

from app.scanner.scoring import score_to_grade

LETTER_TO_GRADE = {"A": 10, "B": 9, "C": 8, "D": 7, "E": 6, "F": 1}
STATUS_LEGACY = {"improved": "greater", "worsened": "less"}


def normalize_grade(grade, score: float | None = None) -> int:
    if isinstance(grade, int) and 1 <= grade <= 10:
        return grade
    if isinstance(grade, str):
        if grade.isdigit():
            return max(1, min(10, int(grade)))
        mapped = LETTER_TO_GRADE.get(grade.upper())
        if mapped is not None:
            return mapped
    if score is not None:
        return score_to_grade(float(score))
    return 1


def normalize_comparison_status(status: str | None) -> str | None:
    if not status:
        return None
    return STATUS_LEGACY.get(status, status)


def normalize_mode(mode: str | None) -> str:
    if mode == "govscan":
        return "standard"
    return mode or "standard"
