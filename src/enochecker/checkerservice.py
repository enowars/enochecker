"""Flask service to run a checker as HTTP service."""

import logging
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

UI_TEMPLATE = """

"""

tiny_poster = """
<script>
// To make testing/posting a bit easier, we can do it from the browser here.
var checker_request_count = 0
var checker_pending_requests = 0
var checker_results = []

function post(str) {
    var xhr = new XMLHttpRequest()
    var started = Date.now()
    xhr.open("POST", "/")
    xhr.setRequestHeader("Content-Type", "application/json")
    xhr.onerror = console.error
    xhr.onload = xhr.onerror = function () {
        checker_results = ["Request " + checker_request_count.toString() + " resulted after " + ((Date.now() - started)/1000) + " s in:\\n" + xhr.responseText + "\\n"].concat(checker_results)
        console.log(xhr.responseText)
        document.getElementById("out").innerText = "<plaintext>\\n\\n" + checker_results.join("\\n")
        checker_request_count++
        checker_pending_requests--
        update_pending()
    }
    xhr.send(str)
    checker_pending_requests++
    update_pending()
}

function update_pending(){
    if (checker_pending_requests === 0) {
        document.getElementById("pending_para").textContent = ""
    } else {
        document.getElementById("pending_para").textContent = checker_pending_requests.toString() + "Requests pending"
    }
}

</script>
<div>
<p>Only select one method from the given list.</p>
<p>Values in brackets are optional, so you can delete those lines if you don't want to specify them.</p>
<button onclick=post(document.getElementById("jsonTextbox").value)>Post</button></div>
<p id="pending_para"></p>
"""


def serialize_spec() -> str:
    """
    Return a checker json spec

    :return: formatted string
    """
    # TODO: update
    return ""


def checker_routes(
    checker_cls: Type["BaseChecker"],
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

        :return: HTML page with info about this service
        """
        logger.info("Request on /")

        serialized_spec = serialize_spec()

        return Response(
            "<h1>Welcome to {} :)</h1>"
            '<p>Expecting POST with a JSON:</p><div><textarea id="jsonTextbox" rows={} cols="80">{}</textarea>{}</div>'
            '<a href="https://www.youtube.com/watch?v=SBClImpnfAg"><br>check it out now</a><div id="out">'.format(
                checker_cls.__name__,
                len(serialized_spec.split("\n")) + 3,
                serialized_spec,
                tiny_poster,
            )
        )

    def serve_checker() -> Response:
        """
        Serve a single checker request.

        The spec needs to be formed according to the spec above.

        :param method: the method to run in a checker.
        :return: jsonified result of the checker.
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

            checker = checker_cls(task_msg)

            checker.logger.info(task_msg)
            res = checker.run()

            result_message = CheckerResultMessage(
                result=res.result, message=res.message
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
                result=CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR,
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

        Includes the name and desired number of flags, havoc and noise per round.

        :return: dictionary with information
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
"""
            )
            raise AttributeError("REQUIRED SERVICE INFO FIELDS NOT SPECIFIED!")

    def get_service_info() -> Response:
        """
        Return JSON representation of the information from :func:`service_info`.

        :return: JSON representation of the service info
        """
        res_json = jsons.dumps(
            service_info(),
            use_enum_name=False,
            key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE,
            strict=True,
        )

        return Response(res_json, mimetype="application/json")

    return index, serve_checker, service_info, get_service_info


def init_service(checker: Type["BaseChecker"]) -> Flask:
    """
    Initialize a flask app that can be used for WSGI or listen directly.

    The Engine may communicate with it over socket.

    :param checker: the checker class to use for check requests.
    :return: a flask app with post and get routes set, ready for checking.
    """
    app = Flask(__name__)
    index, checker_route, service_info, get_service_info = checker_routes(checker)

    app.route("/", methods=["GET"])(index)
    app.route("/", methods=["POST"])(checker_route)
    app.route("/service", methods=["GET"])(get_service_info)

    logger.info(service_info())

    return app  # Start service using service.run(host="0.0.0.0")
