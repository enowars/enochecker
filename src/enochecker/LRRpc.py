from .results import BrokenCheckerException, BrokenServiceException, OfflineException
from requests import post
from os import environ
import json
from asyncio import TimeoutError
BACKEND = environ["CONNHANDLER_URL"]


def rpc_call(target, action_name, runlength, logger=None, **kwargs):
    try:
        if isinstance(action_name, type):
            action_name = type.__name__()
        
        kwargs["address"] = target
        kwargs.setdefault("initial_timeout", 10)
        kwargs.setdefault("long_timeout", runlength)

        # if logger is not None:
        #     logger.debug(kwargs)
        #     logger.debug(json.dumps(kwargs))
            
        req = post("{}/{}".format(BACKEND, action_name), json=kwargs)
        
        if logger is not None:
            logger.debug(f"RPC Result: {req.text}")

        result = req.json()

    except Exception as ex:
        if logger is not None:
            logger.error("Internal RPC Error", exc_info=ex)
        raise BrokenCheckerException

    if result['status'] == 'aborted':
        message = result['exception']['message']
        if logger is not None:
            logger.error("RPC {} {} did not return successfully {}".format(action_name, target, result))
        if result['exception']['type'] == BrokenServiceException.__name__:
            raise BrokenServiceException(message)
        if result['exception']['type'] == OfflineException.__name__:
            raise OfflineException(message)
        if 'Connection' in result['exception']['type']:
            raise ConnectionError(message)
        if result['exception']['type'] == TimeoutError.__name__:
            raise OfflineException(message)

    return result
