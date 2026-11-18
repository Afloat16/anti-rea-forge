"""Synthetic business logic that is deployed only with the trusted service."""

from releaseguard.core import GuardError, parse_json

_SURCHARGES = (19, 23, 29, 31)


def quote(request: bytes) -> dict[str, int]:
    value = parse_json(request)
    if set(value) != {"quantity"} or type(value["quantity"]) is not int or not 0 <= value["quantity"] <= 100_000:
        raise GuardError("Invalid quote request")
    quantity = value["quantity"]
    return {"total": quantity * 37 + _SURCHARGES[quantity % len(_SURCHARGES)]}
