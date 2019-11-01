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
    return "".join(pretty) + "\n  {} {}".format(excp.__class__, excp)


class ELKFormatter(logging.Formatter):
    """
    %(name)s            Name of the logger (logging channel)
    %(levelno)s         Numeric logging level for the message (DEBUG, INFO,
                        WARNING, ERROR, CRITICAL)
    %(levelname)s       Text logging level for the message ("DEBUG", "INFO",
                        "WARNING", "ERROR", "CRITICAL")
    %(pathname)s        Full pathname of the source file where the logging
                        call was issued (if available)
    %(filename)s        Filename portion of pathname
    %(module)s          Module (name portion of filename)
    %(lineno)d          Source line number where the logging call was issued
                        (if available)
    %(funcName)s        Function name
    %(created)f         Time when the LogRecord was created (time.time()
                        return value)
    %(asctime)s         Textual time when the LogRecord was created
    %(msecs)d           Millisecond portion of the creation time
    %(relativeCreated)d Time in milliseconds when the LogRecord was created,
                        relative to the time the logging module was loaded
                        (typically at application startup time)
    %(thread)d          Thread ID (if available)
    %(threadName)s      Thread name (if available)
    %(process)d         Process ID (if available)
    %(message)s         The result of record.getMessage(), computed just as
                        the record is emitted
    """

    def __init__(self, checker, fmt=None, datefmt="%Y-%m-%dT%H:%M:%S%z", style="%"):
        # type: (BaseChecker, str, str, str) -> None
        super().__init__(fmt, datefmt, style)
        self.checker = checker  # type: BaseChecker

    def format(self, record):
        # type: (LogRecord) -> str
        record.stack = self.formatStack(record.stack_info)
        record.asctime = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # stacktrace = ""
        # if record.exc_info:
        #     print("\n\n\n\n\nlog exc_info:", record.exc_info)
        #     stacktrace = traceback.format_exc(record.exc_info)
        # elif record.stack_info:
        #     stacktrace = record.stack_info
        # if record.exc_info is not None:
        #     print("\n\n\n\n\n\n\n", type(record.exc_info), type(record.stack_info))
        #     print("msg: ", record.exc_info[0], "traceback_info :", record.exc_info[1], "traceback_info :" record.stack_info)

        #     import sys
        #     sys.exit(1)
        if record.exc_info is not None:
            exception_info = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_tb(record.exc_info[2], 20),
            }
        else:
            exception_info = None

        log_output = {
            "module": record.module,
            "severity": record.levelname,
            "teamName": self.checker.team,
            "runId": self.checker.run_id,
            "tool": type(self.checker).__name__,
            "flag": self.checker.flag,
            "type": "infrastructure",
            "function": record.funcName,
            "timestamp": record.asctime,
            "round": self.checker.round,
            "relatedRoundId": self.checker.flag_round,
            "flagIndex": self.checker.flag_idx,
            "message": record.getMessage(),
            "exception": exception_info,
            "stacktrace": record.stack_info,
            "serviceName": self.checker.service_name,
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
            "tag": "{}:{}:{}".format(record.name, record.module, record.funcName),
        }
        try:
            r = self.requests.post(self.checker.log_endpoint, json=json)
            if r.status_code != 200:
                print(
                    "Error while logging. Request to {} returned: {}".format(
                        r.status_code, r.text
                    )
                )
        except Exception as ex:
            print("Error while logging: {}".format(ex))
