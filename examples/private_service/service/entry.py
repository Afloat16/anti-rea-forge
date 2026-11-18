"""Adapt an existing authenticated service without adding a network protocol."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from releaseguard.capabilities import ReplayStore, run_authorized_operation

from .operation import quote


def make_quote_handler(issuer_public: Ed25519PublicKey, replay_store: ReplayStore):
    """Call at trusted service startup, then supply authenticated session identity.

    The service owns the issuer key, persistent store and fixed operation. The
    client supplies only exact request bytes and an untrusted signed capability.
    Neither a client authorization boolean nor its chosen key is accepted.
    """
    operation = quote

    def handle(*, authenticated_subject: str, request: bytes, capability: dict):
        return run_authorized_operation(
            capability, issuer_public, replay_store,
            subject=authenticated_subject, audience="owned-quote-service",
            product="owned-quote-app", operation="quote", request=request,
            handler=operation,
        )

    return handle
