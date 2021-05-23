"""Flask service to run a checker as HTTP service."""

import logging
import os
from typing import TYPE_CHECKING, Callable, Tuple, Type

import jsons
from enochecker_core import (
    CheckerInfoMessage,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
)
from flask import Flask, Response, request

from .logging import exception_to_string

if TYPE_CHECKING:  # pragma: no cover
    from .enochecker import BaseChecker

logging.basicConfig(level=logging.DEBUG)
logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)

with open(os.path.join(os.path.dirname(__file__), "post.html")) as f:
    INDEX_PAGE = f.read()


def checker_routes(
    checker_cls: Type["BaseChecker"],
    disable_json_logging: bool,
) -> Tuple[
    Callable[[], Response],
    Callable[[], Response],
    Callable[[], CheckerInfoMessage],
    Callable[[], Response],
]:
    """
    Create a flask app for the given checker class.

    :param checker_cls: The checker class to use
    :return: A flask app that can be passed to a uWSGI server or run using .run().
    """

    def index() -> Response:
        """
        Display general info about this service.

        Includes a web interface for manually sending requests to the service.

        :return: Flask resposne containing the HTML page with info about this service
        """
        logger.info("Request on /")

        return Response(INDEX_PAGE, mimetype="text/html")

    def serve_checker() -> Response:
        """
        Serve a single checker request.

        The request needs to be formed according to the spec of CheckerTaskMessage.

        :return: Flask response containing the CheckerResultMessage as JSON
        """
        try:
            logger.info(request.json)
            try:
                task_msg = jsons.loads(
                    request.get_data(),
                    CheckerTaskMessage,
                    strict=True,
                    key_transformer=jsons.KEY_TRANSFORMER_SNAKECASE,
                )
            except jsons.exceptions.UnfulfilledArgumentError as e:
                return Response(e._msg, status=400)

            checker = checker_cls(task_msg, json_logging=(not disable_json_logging))

            checker.logger.info(task_msg)
            res = checker.run()

            result_message = CheckerResultMessage(
                result=res.result,
                message=res.message,
                attack_info=res.attack_info,
                flag=res.flag,
            )

            res_json = jsons.dumps(
                result_message,
                use_enum_name=False,
                key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
                strict=True,
            )

            checker.logger.info("{}".format(res_json))

            return Response(res_json, mimetype="application/json")

        except Exception as ex:
            logger.error(
                "Returning Internal Error {}.\nTraceback:\n{}".format(
                    ex, exception_to_string(ex)
                ),
                exc_info=ex,
            )
            result_message = CheckerResultMessage(
                result=CheckerTaskResult.INTERNAL_ERROR,
                message=f"Critical checker error occured\n{exception_to_string(ex)}",
            )
            res_json = jsons.dumps(
                result_message,
                use_enum_name=False,
                key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
                strict=True,
            )
            return Response(res_json, mimetype="application/json")

    def service_info() -> CheckerInfoMessage:
        """
        Return technical information about this service.

        Includes the name and supported variants of flags, havoc and noise.

        :return: CheckerInfoMessage filled with the values from the checker
        """
        try:
            service_name: str = getattr(
                checker_cls, "service_name", checker_cls.__name__.split("Checker")[0]
            )

            return CheckerInfoMessage(
                service_name=service_name,
                flag_variants=checker_cls.flag_variants,
                noise_variants=checker_cls.noise_variants,
                havoc_variants=checker_cls.havoc_variants,
                exploit_variants=checker_cls.exploit_variants,
            )

        except Exception:
            logger.error(
                """Service info not specified!
add service_name, flag_variants, havoc_variants and noise_variants as static fields to your CHECKER

Example:
class ExampleChecker(BaseChecker):
    flag_variants  = 1
    noise_variants = 1
    havoc_variants = 1
    exploit_variants = 1
"""
            )
            raise AttributeError("REQUIRED SERVICE INFO FIELDS NOT SPECIFIED!")

    def get_service_info() -> Response:
        """
        Return a Flask response containing the JSON representation of the information from :func:`service_info`.

        :return: Flask response containing the JSON representation of the service info
        """
        res_json = jsons.dumps(
            service_info(),
            use_enum_name=False,
            key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
            strict=True,
        )

        return Response(res_json, mimetype="application/json")

    return index, serve_checker, service_info, get_service_info


def init_service(
    checker: Type["BaseChecker"], disable_json_logging: bool = False
) -> Flask:
    """
    Initialize a flask app that can be used for WSGI or listen directly.

    The Engine may communicate with it over socket.

    :param checker: the checker class to use for check requests.
    :return: a flask app with post and get routes set, ready for checking.
    """
    app = Flask(__name__)
    index, checker_route, service_info, get_service_info = checker_routes(
        checker, disable_json_logging=disable_json_logging
    )

    app.route("/", methods=["GET"])(index)
    app.route("/", methods=["POST"])(checker_route)
    app.route("/service", methods=["GET"])(get_service_info)

    logger.info(service_info())

    return app  # Start service using service.run(host="0.0.0.0")
