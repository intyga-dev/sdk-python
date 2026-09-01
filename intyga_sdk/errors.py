"""Typed exceptions for intyga-sdk.

Mirrors @intyga/sdk's deliberate split: a gateway that ANSWERED with a refusal is a verdict; a
transport failure is an outage. The two must never be conflated — DIV §5a's offline-approval path
exists only for "could not ask", and treating a refusal as unreachability would turn a policy
denial into a different approval route.

Every class subclasses Exception through IntygaError, so pre-existing `except Exception` handling
keeps working; the classes exist so callers can stop string-matching messages.
"""


class IntygaError(Exception):
    """Base class for every error this SDK raises deliberately."""


class GatewayRefused(IntygaError):
    """The gateway answered, and the answer was no (any non-2xx). A verdict, not an outage.

    `status` carries the HTTP status code: 403 is a fail-closed policy refusal, while 401/429 are
    equally deliberate. Usage has not produced 402 since Protected Ops stopped being capped.
    """

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class GatewayUnreachable(IntygaError):
    """The gateway could not be reached at all (DNS failure, refused connection, timeout)."""


class ApprovalRefused(IntygaError):
    """A guarded call did not receive human approval.

    `status` is the challenge's terminal state: DENIED, EXPIRED, or any other non-APPROVED value.
    Raised by `intyga_sdk.guard.require_human_approval` so a wrapped tool cannot run un-approved.
    """

    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status
