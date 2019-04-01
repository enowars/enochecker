import logging
from typing import TYPE_CHECKING, Callable, Type

from flask import Flask, Response
from flask import jsonify
from flask import request

if TYPE_CHECKING:
    from .enochecker import BaseChecker

logging.basicConfig(level=logging.DEBUG)
logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)


def index():
    # type: () -> str
    """
    Some info about this service
    :return: Printable fun..
    """
    logging.info("Request on /")
    return '<a href="https://www.youtube.com/watch?v=SBClImpnfAg">check it out now</a>'


# method=None, address=None, team_name=None, round=None, flag=None, call_idx=None,
# max_time=None, port=None, storage_dir=DB_DEFAULT_DIR, from_args=True):
def checker_route(checker_cls):
    # type: (Type[BaseChecker]) -> Callable[[str], Response]
    """
    Creates a flask app for the given checker class.
    :param checker_cls: The checker class to use
    :return: A flask app that can be passed to a uWSGI server or run using .run().
    """

    def serve_checker(method):
        # type: (str) -> Response
        """
        Serves a single checker request
        :param method: the method to run in a checker.
        :return: jsonified result of the checker.
        """
        logger.info(request.json)
        json = request.json
        # TODO: Find a nice way to set service port? Is that even needed?
        checker = checker_cls(method=method, address=json["Address"], team_name=json["TeamName"],
                              round=json["CurrentRoundId"],
                              flag=json["Payload"], call_idx=json["TaskIndex"], max_time=json["MaxRunningTime"],
                              port=0x70D0)
        result = checker.run(method).name
        logger.info("Run resulted in {}: {}".format(result, request.json))
        return jsonify({"result": result})

    return serve_checker


def init_service(checker):
    # type: (Type[BaseChecker]) -> Flask

    app = Flask(__name__)
    app.route("/", methods=["GET"])(index)

    app.route('/<method>', methods=['POST'])(
        checker_route(checker)
    )

    return app  # Start service using service.run(host="0.0.0.0")
