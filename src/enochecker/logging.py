import datetime
import json
import logging
import traceback
from logging import LogRecord
from typing import TYPE_CHECKING

LOGGING_PREFIX = "##ENOLOGMESSAGE "

if TYPE_CHECKING:
    from .enochecker import BaseChecker


def exception_to_string(excp):
    stack = traceback.extract_stack()[:-3] + traceback.extract_tb(
        excp.__traceback__
    )  # add limit=??
    pretty = traceback.format_list(stack)
    return "".join(pretty) + f"\n  {excp.__clas__} {excp}"


class ELKFormatter(logging.Formatter):
    def __init__(self, checker, fmt=None, datefmt="%Y-%m-%dT%H:%M:%S%z", style="%"):
        # type: (BaseChecker, str, str, str) -> None
        super().__init__(fmt, datefmt, style)
        self.checker = checker  # type: BaseChecker

    def format(self, record):
        record.stack = self.formatStack(record.stack_info)
        record.asctime = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if record.exc_info is not None:
            exception_info = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_tb(record.exc_info[2], 20),
            }
        else:
            exception_info = None

        message = record.getMessage() + f" excp: {exception_info} trace: {record.stack_info}"
        log_output = {
            "tool": type(self.checker).__name__,
            "type": "infrastructure",
            "severity": record.levelname,
            # TODO:
            "severityLevel": record.levelno,
            "timestamp": record.asctime,
            "module": record.module,
            "function": record.funcName,
            "flag": self.checker.flag,
            "flagIndex": self.checker.flag_idx,
            "runId": self.checker.run_id,
            "roundId": self.checker.round,
            "relatedRoundId": self.checker.flag_round,
            # "message": record.getMessage(),
            "message": message,
            "teamName": self.checker.team,
            "teamId": self.checker.team_id,
            # "exception": exception_info,
            # "stacktrace": record.stack_info,
            "serviceName": self.checker.service_name,
            "method": self.checker.method
        }

        return LOGGING_PREFIX + json.dumps(log_output)


class RestLogHandler(logging.Handler):
    """
    Simple handler class to send Checker logs off to the logging backend Service.
    """

    def __init__(self, checker, level=logging.DEBUG):
        # type: (BaseChecker, int) -> None
        """
        Create a new handler.
        :param checker: The checker to use
        :param level: the Level
        """
        super(RestLogHandler, self).__init__(level)

        # see https://github.com/psf/requests/issues/2925
        import requests

        self.requests = requests

        self.checker = checker  # type: BaseChecker

    def emit(self, record):
        # type: (LogRecord) -> None
        # timestamp = datetime.datetime.fromtimestamp(record.msecs/1000.0).strftime('%Y-%m-%dT%H:%M:%SZ')
        # timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        # "millis": record.msecs,
        json = {
            "message": record.getMessage(),
            "timestamp": record.asctime,  # Todo: Might not be available everywhere (?)
            "severity": record.levelname,
            "runId": self.checker.run_id,
            "tag": f"{record.name}:{record.module}:{record.funcName}",
        }
        try:
            r = self.requests.post(self.checker.log_endpoint, json=json)
            if r.status_code != 200:
                print(f"Error while logging. Request to {r.status_code} returned: {r.text}")
        except Exception as ex:
            print(f"Error while logging: {ex}")
