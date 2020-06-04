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
    return "".join(pretty) + f"\n  {excp.__class__} {excp}"


class ELKFormatter(logging.Formatter):
    def __init__(
        self,
        checker: "BaseChecker",
        fmt: str = None,
        datefmt: str = "%Y-%m-%dT%H:%M:%S%z",
        style: str = "%",
    ) -> None:
        super().__init__(fmt, datefmt, style)
        self.checker: "BaseChecker" = checker

    def format(self, record):
        record.stack = self.formatStack(record.stack_info)
        record.asctime = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        message = record.getMessage()
        if record.exc_info:
            eno = record.exc_info
            stacktrace = "".join(
                traceback.format_exception(None, eno, eno.__traceback__)
            )
            message += f" excp: {stacktrace}"
        if record.stack_info:
            message += f" trace: {record.stack}"

        log_output = {
            "tool": type(self.checker).__name__,
            "type": "infrastructure",
            "severity": record.levelname,
            "severityLevel": max(0, record.levelno // 10 - 1),
            "timestamp": record.asctime,
            "module": record.module,
            "function": record.funcName,
            "flag": self.checker.flag,
            "flagIndex": self.checker.flag_idx,
            "runId": self.checker.run_id,
            "roundId": self.checker.round,
            "relatedRoundId": self.checker.flag_round,
            "message": message,
            "teamName": self.checker.team,
            "teamId": self.checker.team_id,
            "serviceName": self.checker.service_name,
            "method": self.checker.method,
        }

        return LOGGING_PREFIX + json.dumps(log_output)


class RestLogHandler(logging.Handler):
    """
    Simple handler class to send Checker logs off to the logging backend Service.
    """

    def __init__(self, checker: "BaseChecker", level: int = logging.DEBUG) -> None:
        """
        Create a new handler.
        :param checker: The checker to use
        :param level: the Level
        """
        super().__init__(level)

        # see https://github.com/psf/requests/issues/2925
        import requests

        self.requests = requests

        self.checker: "BaseChecker" = checker

    def emit(self, record: LogRecord) -> None:
        # timestamp = datetime.datetime.fromtimestamp(record.msecs/1000.0).strftime('%Y-%m-%dT%H:%M:%SZ')
        # timestamp = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        # "millis": record.msecs,
        if not self.checker.log_endpoint:
            print("Error while logging, no log endpoint specified")
            return

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
                print(
                    f"Error while logging. Request to {r.status_code} returned: {r.text}"
                )
        except Exception as ex:
            print(f"Error while logging: {ex}")
