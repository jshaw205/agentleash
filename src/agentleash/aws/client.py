"""A boto3 session wrapper that can only make allowlisted read-only calls.

Two layers stop a write from ever reaching AWS:

1. ``ReadOnlySession.call`` checks the allowlist before building a request.
2. A botocore ``before-call`` hook on every client re-checks the operation, so a
   client method called directly (bypassing ``call``) is refused as well.
"""

from __future__ import annotations

from typing import Any

from botocore import xform_name

from agentleash.aws.allowlist import is_allowed


class OperationNotAllowed(RuntimeError):
    """Raised when code tries to call an AWS operation outside the allowlist."""


def _guard(service: str):
    def before_call(model, **_kwargs):
        if not is_allowed(service, model.name):
            raise OperationNotAllowed(f"{service}:{model.name} is not on the read-only allowlist")

    return before_call


class ReadOnlySession:
    def __init__(self, profile: str | None = None, region: str | None = None, session=None):
        if session is None:
            import boto3

            session = boto3.Session(profile_name=profile, region_name=region)
        self._session = session
        self._clients: dict[tuple[str, str | None], Any] = {}

    def client(self, service: str, region: str | None = None):
        key = (service, region)
        if key not in self._clients:
            client = self._session.client(service, region_name=region)
            client.meta.events.register("before-call", _guard(service))
            self._clients[key] = client
        return self._clients[key]

    def call(self, service: str, operation: str, region: str | None = None, **params):
        if not is_allowed(service, operation):
            raise OperationNotAllowed(f"{service}:{operation} is not on the read-only allowlist")
        client = self.client(service, region)
        method = getattr(client, xform_name(operation))
        return method(**params)

    def paginate(self, service: str, operation: str, region: str | None = None, **params):
        if not is_allowed(service, operation):
            raise OperationNotAllowed(f"{service}:{operation} is not on the read-only allowlist")
        paginator = self.client(service, region).get_paginator(xform_name(operation))
        yield from paginator.paginate(**params)
