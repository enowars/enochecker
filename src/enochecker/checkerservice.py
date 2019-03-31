import logging

from flask import Flask
from flask import jsonify
from flask import g, request

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)


@app.route('/', methods=['GET'])
def index():
    logging.info("Request on /")
    return "Checker {} running".format(_checker.__name__)


# method=None, address=None, team_name=None, round=None, flag=None, call_idx=None,
# max_time=None, port=None, storage_dir=DB_DEFAULT_DIR, from_args=True):
@app.route('/<method>', methods=['POST'])
def checker(method):
    logger.info(request.json)
    json = request.json
    # TODO: Find a nice way to set service port? Is that even needed?
    checker = _checker(method=method, address=json["Address"], team_name=json["TeamName"], round=json["CurrentRoundId"],
                       flag=json["Payload"], call_idx=json["TaskIndex"], max_time=json["MaxRunningTime"], port=0x70D0)
    result = checker.run(method).name
    logger.info("Run resulted in {}: {}".format(result, request.json))
    return jsonify({"result": result})


def listen(checker, port):
    # type: (enochecker.BaseChecker, int) -> None
    # with app.app_context():
    #    setattr(g, "checker", checker)
    global _checker
    print(checker)
    _checker = checker
    app.run(host="0.0.0.0", port=port)
