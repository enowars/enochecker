"""Utilities for sending log messages to a central ELK."""

import datetime
import logging
import traceback
from logging import LogRecord
from typing import TYPE_CHECKING

import jsons
from enochecker_core import EnoLogMessage

LOGGING_PREFIX = "##ENOLOGMESSAGE "

if TYPE_CHECKING:  # pragma: no cover
    from .enochecker import BaseChecker


def exception_to_string(excp: Exception) -> str:
    """
    Format an exception as a string.

    Limits the length of the traceback to 3.
    :param ecxp: the exception to format
    :return: The formatted string
    """
    stack = traceback.extract_stack()[:-3] + traceback.extract_tb(
        excp.__traceback__
    )  # add limit=??
    pretty = traceback.format_list(stack)
    return "".join(pretty) + f"\n  {excp.__class__} {excp}"


class ELKFormatter(logging.Formatter):
    """Format log messages for a central ELK."""

    def __init__(
        self,
        checker: "BaseChecker",
        fmt: str = None,
        datefmt: str = "%Y-%m-%dT%H:%M:%S%z",
        style: str = "%",
    ) -> None:
        """
        Initialize a new formatter.

        :param checker: The checker instance to which this formatter belongs, needed to include information about the service in the messages.
        :param fmt: format string passed to :class:`logging.Formatter`
        :param datefmt: date format string passed to :class:`logging.Formatter`
        :param style: style string passed to :class:`logging.Formatter`
        """
        super().__init__(fmt, datefmt, style)
        self.checker: "BaseChecker" = checker

    def format(self, record: LogRecord) -> str:
        """
        Format a LogRecord as a string.

        :param record: the record to format
        :return: the formatted string
        """
        record.asctime = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        message = record.getMessage()
        if record.exc_info:
            eno = record.exc_info
            stacktrace = "".join(traceback.format_exception(None, eno[1], eno[2]))
            message += f" excp: {stacktrace}"
        if record.stack_info:
            stack = self.formatStack(record.stack_info)
            message += f" trace: {stack}"

        log_message = EnoLogMessage(
            tool=type(self.checker).__name__,
            type="infrastructure",
            severity=record.levelname,
            severity_level=max(0, record.levelno // 10 - 1),
            timestamp=record.asctime,
            message=message,
            module=record.module,
            function=record.funcName,
            service_name=self.checker.service_name,
            method=self.checker.method.value if self.checker.method else None,
            task_id=self.checker.task_id,
            team_id=self.checker.team_id,
            team_name=self.checker.team_name,
            current_round_id=self.checker.current_round_id,
            related_round_id=self.checker.related_round_id,
            flag=self.checker.flag,
            variant_id=self.checker.variant_id,
            task_chain_id=self.checker.task_chain_id,
            flag_regex=self.checker.flag_regex,
            flag_hash=self.checker.flag_hash,
            attack_info=self.checker.attack_info,
        )

        return LOGGING_PREFIX + jsons.dumps(
            log_message,
            use_enum_name=False,
            key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
            strict=True,
        )
