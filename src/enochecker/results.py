"""Collection of Exception classes to signal the status of the service being checked."""

from abc import ABC
from enum import IntEnum
from flask import jsonify, Response
from typing import Dict, Optional


class Result(IntEnum):
    """Result Values to be returned from a Checker."""

    INTERNAL_ERROR: int = -1  # The checker crashed
    OK: int = 0  # Everything is alright
    MUMBLE: int = 1  # (ENOFLAG/mumble)
    OFFLINE: int = 2  # It's dead, jim

    # noinspection PyTypeChecker
    @classmethod
    def is_valid(cls, value: int) -> bool:
        """
        Return if the value is part of this Enum.

        :param value: the value
        :return: True, if value is part of this Enum
        """
        return any(value == item.value for item in cls)


class CheckerResult():
    def __init__(self, result: Result, message: Optional[str] = None) -> None:
        self.result = result
        self.message = message

    @staticmethod
    def from_exception(e: Exception, public_message=None) -> 'CheckerResult':
        """ Converts a given Exception to an extended CheckerResult including Message
        public_message isn't used anywhere yet"""

        if isinstance(e, EnoException):
            return CheckerResult(
                result=e.result,
                message=e.message
            )

        else:
            return CheckerResult(
                Result.INTERNAL_ERROR,
                message=None
            )

    def to_dict(self) -> Dict[str, Optional[str]]:
        """ Returns a dictionary representation of a given CheckerResult """
        return {
            'result': self.result.name,
            'message': self.message,
        }

    def jsonify(self) -> Response:
        """ Converts a Checkerresult to a valid json response (hopefully) according to spec """
        return jsonify(self.to_dict())


class EnoException(Exception, ABC):
    """Base error including the Result. Raise a subclass of me once we know what to do."""

    result: Result = Result.INTERNAL_ERROR

    def __init__(self, *args, scoreboard_message=None, **kwargs):
        self.message = scoreboard_message


class BrokenServiceException(EnoException):
    """Indicates a broken Service."""

    result: Result = Result.MUMBLE


class OfflineException(EnoException):
    """Service was not reachable (at least once) during our checks."""

    result: Result = Result.OFFLINE


class BrokenCheckerException(EnoException):
    """
    Shouldn't be raised ever since we catch all abstract Errors.

    Used internally if something goes horribly wrong.
    """

    result: Result = Result.INTERNAL_ERROR
