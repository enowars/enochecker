import collections
import logging
import sys
from typing import TYPE_CHECKING, Callable, Type, Any, List, Union, Dict, Tuple
from elasticapm.contrib.flask import ElasticAPM

from flask import Flask, Response
from flask import jsonify
from flask import request

from .enochecker import Result
from .utils import snake_caseify

if TYPE_CHECKING:
    from .enochecker import BaseChecker

logging.basicConfig(level=logging.DEBUG)
logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)

# ElasticSearch performance monitoring
apm = ElasticAPM()

Optional = collections.namedtuple("Optional", "key type default")
Required = collections.namedtuple("Required", "key type")

CHECKER_METHODS = [
    "putflag",
    "getflag",
    "putnoise",
    "getnoise",
    "havoc"
]  # type: List[str]

# The json spec a checker request follows.
spec = [
    Required("method", CHECKER_METHODS),  # method to execute
    Required("address", str),  # address to check
    Optional("runId", int, 0),  # internal ID of this run inside our db
    Optional("team", str, "FakeTeam"),  # the team name
    Optional("round", int, 0),  # which tick we are in
    Optional("roundLength", int, 300),  # the default tick time
    Optional("flag", str, "ENOTESTFLAG"),  # the flag or noise to drop or get
    Optional("flagIndex", int, 0),  # the index of this flag in a given round (starts at 0)
    Optional("timeout", int, 30),  # timeout we have for this run
    Optional("logEndpoint", str, None)  # endpoint to send runs to
]  # type: List[Union[Required, Optional]]

tiny_poster = """
<script>
// To make testing/posting a bit easier, we can do it from the browser here.
function post(str) {
    var xhr = new XMLHttpRequest()
    xhr.open("POST", "/")
    xhr.setRequestHeader("Content-Type", "application/json")
    xhr.onerror = console.error
    xhr.onload = xhr.onerror = function () {
        console.log(xhr.responseText)
        document.getElementById("out").innerText = "<plaintext>\\n\\n" + xhr.responseText
    }
    xhr.send(str)
}
</script>
<div>
<button onclick=post(document.getElementById("jsonTextbox").value)>Post</button></div>
"""


def check_type(name, val, expected_type):
    # type: (str, str, Any) -> None
    """
    returns and converts if necessary
    :param name: the name of the value
    :param val: the value to check
    :param expected_type: the expected type
    """
    if isinstance(expected_type, list):
        if val not in expected_type:
            # The given type is not in the list of allowed members.
            raise ValueError("{} is not a member of expected list {}, got {}".format(name, expected_type, val))
    elif not isinstance(val, expected_type):
        raise ValueError(
            "{} should be a '{}' but is of type '{}'.".format(name, expected_type.__name__, type(val).__name__))


def stringify_spec_entry(entry):
    # type: (Union[Optional, Required]) -> str
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
    raise ValueError("Could not stringify unknown entry type {}: {}".format(type(entry), entry))


def serialize_spec(spec):
    # type: (List[Union[Optional, Required]]) -> str
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


def json_to_kwargs(json, spec):
    # type: (Dict[str, Any], List[Union[Optional, Required]]) -> Dict[str, Any]
    """
    Generates a kwargs dict from a json.
    Will copy all elements from json to the dict, rename all keys to snake_case and Index to idx.
    In case the spec fails, errors out with ValueError.
    :param json:  the json
    :param spec: the spec
    :return: kwargs dict.
    """
    ret = {}

    def key_to_name(key):
        # type: (str)->str
        key = key.replace("Index", "Idx")  # -> flagIndex -> flag_idx
        return snake_caseify(key)

    for entry in spec:
        if entry.key not in json:
            if isinstance(entry, Optional):
                ret[key_to_name(entry.key)] = entry.default
            else:
                raise ValueError("Required parameter {} is missing.".format(stringify_spec_entry(entry)))
        else:
            val = json[entry.key]
            check_type(entry.key, val, entry.type)
            ret[key_to_name(entry.key)] = val
    return ret


def checker_routes(checker_cls):
    # type: (Type[BaseChecker]) -> Tuple[Callable[[],Response], Callable[[], Response]]
    """
    Creates a flask app for the given checker class.
    :param checker_cls: The checker class to use
    :return: A flask app that can be passed to a uWSGI server or run using .run().
    """

    def index():
        # type: () -> Response
        """
        Some info about this service
        :return: Printable fun..
        """
        logging.info("Request on /")

        return Response('<h1>Welcome to {} :)</h1>'
                        '<p>Expecting POST with a JSON:</p><div><textarea id="jsonTextbox" rows={} cols="80">{}</textarea>{}</div>'
                        '<a href="https://www.youtube.com/watch?v=SBClImpnfAg"><br>check it out now</a><div id="out">'.format(
                checker_cls.__name__, len(spec) + 3, serialize_spec(spec), tiny_poster))

    def serve_checker():
        # type: () -> Response
        """
        Serves a single checker request.
        The spec needs to be formed according to the spec above.
        :param method: the method to run in a checker.
        :return: jsonified result of the checker.
        """
        try:
            logger.info(request.json)
            json = request.get_json(force=True)

            kwargs = json_to_kwargs(json, spec)

            checker = checker_cls(**kwargs)
            checker.logger.info(request.json)
            res = checker.run().name
            checker.logger.info("Run resulted in {}: {}".format(res, request.json))
            return jsonify({"result": res})
        except Exception as ex:
            print(ex)
            logger.error("Returning Internal Error {}.".format(ex), exc_info=ex)
            return jsonify({
                "result": Result.INTERNAL_ERROR.name,
                "message": str(ex)
            })

    return index, serve_checker


def init_service(checker):
    # type: (Type[BaseChecker]) -> Flask
    """
    Initializes a flask app that can be used for WSGI or listen directly.
    The Engine may Communicate with it over socket.
    :param checker: the checker class to use for check requests.
    :return: a flask app with post and get routes set, ready for checking.
    """
    app = Flask(__name__)
    index, checker_route = checker_routes(checker)

    app.route("/", methods=["GET"])(index)
    app.route('/', methods=['POST'])(checker_route)

    if "run" not in sys.argv:
        # ElasticSearch Performance Monitoring (disabled on commandline)
        apm.init_app(app, service_name=checker.__name__.split("Checker")[0])  # secret_token=SECRET)

    return app  # Start service using service.run(host="0.0.0.0")
