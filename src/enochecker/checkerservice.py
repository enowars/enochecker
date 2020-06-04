import collections
import json
import logging
import sys
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Tuple, Type, Union

from flask import Flask, Response, jsonify, request

from .logging import exception_to_string
from .results import Result
from .utils import snake_caseify

# from elasticapm.contrib.flask import ElasticAPM

if TYPE_CHECKING:
    from .enochecker import BaseChecker

logging.basicConfig(level=logging.DEBUG)
logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)

# ElasticSearch performance monitoring
# apm = ElasticAPM()

Optional = collections.namedtuple("Optional", "key type default")
Required = collections.namedtuple("Required", "key type")

CHECKER_METHODS: List[str] = [
    "putflag",
    "getflag",
    "putnoise",
    "getnoise",
    "havoc",
    "exploit",
]

# The json spec a checker request follows.
spec: List[Union[Required, Optional]] = [
    Required("method", CHECKER_METHODS),  # method to execute
    Required("address", str),  # address to check
    Optional("runId", int, 0),  # internal ID of this run inside our db
    Optional("teamName", str, "FakeTeam"),  # the team name
    Optional("teamId", int, 1),  # team ID
    Optional("roundId", int, 0),  # which tick we are in
    Optional("relatedRoundId", int, 0),  # Flag-Related
    Optional("roundLength", int, 300),  # the default tick time
    Optional("flag", str, "ENOTESTFLAG"),  # the flag or noise to drop or get
    Optional("flagIndex", int, 0),
    Optional("timeout", int, 30),  # timeout we have for this run
    Optional("logEndpoint", str, None),  # endpoint to send runs to
]

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


def check_type(name: str, val: str, expected_type: Any) -> None:
    """
    returns and converts if necessary
    :param name: the name of the value
    :param val: the value to check
    :param expected_type: the expected type
    """
    if isinstance(expected_type, list):
        if val not in expected_type:
            # The given type is not in the list of allowed members.
            raise ValueError(
                "{} is not a member of expected list {}, got {}".format(
                    name, expected_type, val
                )
            )
    elif not isinstance(val, expected_type):
        raise ValueError(
            "{} should be a '{}' but is of type '{}'.".format(
                name, expected_type.__name__, type(val).__name__
            )
        )


# def generate_form(spec):
#    form = "<form class=\"json-form\">\n"
#    for entry in spec:
#        if isinstance(entry, Required):


def stringify_spec_entry(entry: Union[Optional, Required]) -> str:
    """Make a nice string out of it."""
    entrytype = entry.type
    if isinstance(entrytype, type):
        entrytype = entrytype.__name__
    # ugly hack: We don't want a list to be ['like', 'this'] but ["with", "json", "quotes"]...
    entrytype = "{}".format(entrytype).replace("'", '"')
    if isinstance(entry, Required):
        return '"{}": {}'.format(entry.key, entrytype)
    if isinstance(entry, Optional):
        return '"{}": ({} ?? {})'.format(entry.key, entrytype, entry.default)
    raise ValueError(
        "Could not stringify unknown entry type {}: {}".format(type(entry), entry)
    )


def serialize_spec(spec: List[Union[Optional, Required]]) -> str:
    """
    Prints a checker json spec in a readable multiline format
    :param spec: a spec
    :return: formatted string
    """
    ret = "{\n"
    for entry in spec:
        if ret != "{\n":
            ret += ",\n"
        ret += "  " + stringify_spec_entry(entry)
    return ret + "\n}"


def assert_types(
    json: Dict[str, Any], spec: List[Union[Optional, Required]]
) -> Dict[str, Any]:
    """
    Generates a kwargs dict from a json.
    Will copy all elements from json to the dict, rename all keys to snake_case and Index to idx.
    In case the spec fails, errors out with ValueError.
    :param json:  the json
    :param spec: the spec
    :return: kwargs dict.
    """
    ret = {}

    def key_to_name(key: str) -> str:
        key = key.replace("Index", "Idx")  # -> flagIndex -> flag_idx
        key = key.replace("relatedRoundId", "flagRound")
        return snake_caseify(key)

    for entry in spec:
        if entry.key not in json:
            if isinstance(entry, Optional):
                ret[key_to_name(entry.key)] = entry.default
            else:
                raise ValueError(
                    "Required parameter {} is missing.".format(
                        stringify_spec_entry(entry)
                    )
                )
        else:

            val = json[entry.key]
            if val is None and isinstance(entry, Optional):
                print("Inserted default")
                val = entry.default

            if entry.key == "method" and val == "havok":
                logger.warning("Ignoring Havok -- calling Havoc instead")
                val = "havoc"
            check_type(entry.key, val, entry.type)
            ret[key_to_name(entry.key)] = val
    return ret


def checker_routes(
    checker_cls: Type["BaseChecker"],
) -> Tuple[
    Callable[[], Response],
    Callable[[], Response],
    Callable[[], Dict[str, Union[str, int]]],
    Callable[[], str],
]:
    """
    Creates a flask app for the given checker class.
    :param checker_cls: The checker class to use
    :return: A flask app that can be passed to a uWSGI server or run using .run().
    """

    def index() -> Response:
        """
        Some info about this service
        :return: Printable fun..
        """
        logging.info("Request on /")

        return Response(
            "<h1>Welcome to {} :)</h1>"
            '<p>Expecting POST with a JSON:</p><div><textarea id="jsonTextbox" rows={} cols="80">{}</textarea>{}</div>'
            '<a href="https://www.youtube.com/watch?v=SBClImpnfAg"><br>check it out now</a><div id="out">'.format(
                checker_cls.__name__, len(spec) + 3, serialize_spec(spec), tiny_poster
            )
        )

    def serve_checker() -> Response:
        """
        Serves a single checker request.
        The spec needs to be formed according to the spec above.
        :param method: the method to run in a checker.
        :return: jsonified result of the checker.
        """
        try:
            logger.info(request.json)
            req_json = request.get_json(force=True)

            kwargs = assert_types(req_json, spec)

            checker = checker_cls(request_dict=kwargs, **kwargs)

            checker.logger.info(request.json)
            res = checker.run().name

            req_json["result"] = res
            req_json = json.dumps(req_json)

            # checker.logger.info("Run resulted in {}: {}".format(res, request.json))
            checker.logger.info("{}".format(req_json))

            return jsonify({"result": res})
        except Exception as ex:
            print(ex)
            logger.error(
                "Returning Internal Error {}.\nTraceback:\n{}".format(
                    ex, exception_to_string(ex)
                ),
                exc_info=ex,
            )
            return jsonify(
                {
                    "result": Result.INTERNAL_ERROR.name,
                    "message": str(ex),
                    "traceback": exception_to_string(ex),
                }
            )

    def service_info() -> Dict[str, Union[str, int]]:
        """
        Serves a single checker request.
        The spec needs to be formed according to the spec above.
        :param method: the method to run in a checker.
        :return: jsonified result of the checker.
        """
        try:
            service_name: str = getattr(
                checker_cls, "service_name", checker_cls.__name__.split("Checker")[0]
            )

            info_dict = {
                "serviceName": service_name,
                "flagCount": checker_cls.flag_count,
                "havocCount": checker_cls.havoc_count,
                "noiseCount": checker_cls.noise_count,
            }

            assert isinstance(info_dict["serviceName"], str)
            assert isinstance(info_dict["flagCount"], int)
            assert isinstance(info_dict["havocCount"], int)
            assert isinstance(info_dict["noiseCount"], int)

            return info_dict  # type: ignore # (mypy would infer Dict[str, object] instead)

        except Exception:
            print("SERVICE INFO NOT SPECIFIED!!!11ELF!")
            print(
                "add service_name, flag_count, havoc_count and noise_count as \
static fields to your CHECKER\n"
            )
            print(
                """
Example:
class ExampleChecker(BaseChecker):
    flag_count  = 1
    noise_count = 1
    havoc_count = 1
"""
            )
            raise AttributeError("REQUIRED SERVICE INFO FIELDS NOT SPECIFIED!")

    def get_service_info() -> str:
        return jsonify(service_info())

    return index, serve_checker, service_info, get_service_info


def init_service(checker: Type["BaseChecker"]) -> Flask:
    """
    Initializes a flask app that can be used for WSGI or listen directly.
    The Engine may Communicate with it over socket.
    :param checker: the checker class to use for check requests.
    :return: a flask app with post and get routes set, ready for checking.
    """
    app = Flask(__name__)
    index, checker_route, service_info, get_service_info = checker_routes(checker)

    app.route("/", methods=["GET"])(index)
    app.route("/", methods=["POST"])(checker_route)
    app.route("/service", methods=["GET"])(get_service_info)

    print(service_info())

    if "run" not in sys.argv:
        # ElasticSearch Performance Monitoring (disabled on commandline)
        # apm.init_app(app, service_name=checker.__name__.split("Checker")[0])  # secret_token=SECRET)
        pass

    return app  # Start service using service.run(host="0.0.0.0")
