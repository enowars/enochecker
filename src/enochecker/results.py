"""Collection of Exception classes to signal the status of the service being checked."""

from abc import ABC
from typing import Optional

from enochecker_core import CheckerTaskResult


class CheckerResult:
    def __init__(
        self,
        result: CheckerTaskResult,
        message: Optional[str] = None,
        attack_info: Optional[str] = None,
        flag: Optional[str] = None,
    ) -> None:

        if message == "":
            message = None

        self.result = result
        self.message = message
        self.attack_info = attack_info
        self.flag = flag

    @staticmethod
    def from_exception(e: Exception) -> "CheckerResult":
        """Converts a given Exception to an extended CheckerResult including Message
        public_message isn't used anywhere yet"""

        if isinstance(e, EnoException):
            message = str(e)
            return CheckerResult(result=e.result, message=message)

        else:
            return CheckerResult(CheckerTaskResult.INTERNAL_ERROR, message=None)


class EnoException(Exception, ABC):
    """Base error including the Result. Raise a subclass of me once we know what to do."""

    result: CheckerTaskResult = CheckerTaskResult.INTERNAL_ERROR

    def __init__(
        self,
        message: Optional[str],
        internal_message: Optional[str] = None,
    ):
        self.message: Optional[str] = message
        self.internal_message: Optional[str] = internal_message

    def __str__(self) -> str:
        return self.message if self.message else ""

    def message_contains(self, flag: Optional[str]) -> bool:
        """" If the string is in the message """
        if not self.message:
            return False
        if not flag:
            return False
        return flag in self.message


class BrokenServiceException(EnoException):
    """Indicates a broken Service."""

    result: CheckerTaskResult = CheckerTaskResult.MUMBLE


class OfflineException(EnoException):
    """Service was not reachable (at least once) during our checks."""

    result: CheckerTaskResult = CheckerTaskResult.OFFLINE


class BrokenCheckerException(EnoException):
    """
    Shouldn't be raised ever since we catch all abstract Errors.

    Used internally if something goes horribly wrong.
    """

    result: CheckerTaskResult = CheckerTaskResult.INTERNAL_ERROR
