from requests import post
from os import environ

BACKEND = environ["CONNHANDLER_URL"]


def Rpc_call(action_name, runlength, **kwargs):
    try:
        if isinstance(action_name, type):
            action_name = type.__name__()
        
        kwargs.setdefault("initial_timeout", 10)
        kwargs.setdefault("long_timeout", runlength)

        req = post("{}/{}".format(BACKEND, action_name), data=kwargs)
        result = req.json()

    except Exception:
        raise
