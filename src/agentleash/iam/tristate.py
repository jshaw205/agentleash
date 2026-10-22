"""Three-valued logic: a statement may be known to apply, known not to, or unknown."""

from enum import Enum


class Tri(Enum):
    FALSE = 0
    UNKNOWN = 1
    TRUE = 2

    def __bool__(self) -> bool:  # pragma: no cover - guard against accidental use
        raise TypeError("Tri has no truth value; compare with Tri.TRUE explicitly")

    def __invert__(self) -> "Tri":
        return {Tri.TRUE: Tri.FALSE, Tri.FALSE: Tri.TRUE, Tri.UNKNOWN: Tri.UNKNOWN}[self]


def tri(value: bool) -> Tri:
    return Tri.TRUE if value else Tri.FALSE


def all_of(*values: Tri) -> Tri:
    """Kleene AND: false wins, then unknown."""
    return min(values, key=lambda v: v.value, default=Tri.TRUE)


def any_of(*values: Tri) -> Tri:
    """Kleene OR: true wins, then unknown."""
    return max(values, key=lambda v: v.value, default=Tri.FALSE)
