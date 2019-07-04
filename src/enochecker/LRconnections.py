from abc import ABC, abstractmethod

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.background import BackgroundTask

from asyncio import wait_for, TimeoutError
from functools import partial
from traceback import format_tb

from sys import exc_info


class LR_Action(ABC):

    def __init__(self, request_params):
        self.request = request_params

    @abstractmethod
    async def initial_call(self):
        pass
    
    @abstractmethod
    async def background_call(self):
        pass

    @abstractmethod
    async def cleanup(self):
        pass


class LR_Handler(Starlette):
    def __init__(self, lr_callables, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for call in lr_callables:

            p_call = partial(self._callwrapper, call)
            self.add_route(f"/{call.__name__}", p_call, methods=["POST"])

            print(f"/{call.__name__}")

    @staticmethod
    async def _callwrapper(
         lr_callable, 
         scope, recieve, send, 
         *args, **rkwargs
         ):
        
        async def __bg_task(timeout):  # lr_action: LR_Action, 
            nonlocal lr_action
            try:
                await wait_for(lr_action.background_call(), timeout)
                print({
                      "status": "FINISHED",
                      "exception": None
                      })

            except TimeoutError:
                exc_inf = exc_info()
                print({
                      "status": "Timeout",
                      "exception": {
                        "type":    exc_inf[0].__name__,
                        "message": str(exc_inf[1]),
                        "trace ":  format_tb(exc_inf[2])
                        }
                      })

            except Exception:
                exc_inf = exc_info()
                print({
                      "status": "Error",
                      "exception": {
                        "type":    exc_inf[0].__name__,
                        "message": str(exc_inf[1]),
                        "trace ":  format_tb(exc_inf[2])
                        }
                      })

            finally:
                try:
                    await lr_action.cleanup()
                except Exception:
                    exc_inf = exc_info()
                    print({
                      "status": "cleanup failed",
                      "exception": {
                        "type":    exc_inf[0].__name__,
                        "message": str(exc_inf[1]),
                        "trace ":  format_tb(exc_inf[2])
                        }
                      })
                del lr_action

        request = Request(scope, recieve)
        kwargs = await request.json()

        lr_action = lr_callable(kwargs)
        # lr_action = None
        try:
            # initial Call
            continue_with_bg, ret_dict = await wait_for(lr_action.initial_call(), kwargs['initial_timeout'])
            print("initial call succeded")
            # Background Task
            
            if continue_with_bg:
                task = BackgroundTask(__bg_task, kwargs['long_timeout'])
            else:
                task = None

        except Exception:
            print("got Exception")
            cleanup_failed = None
            exc_inf = exc_info()
            try:
                await lr_action.cleanup()
            except Exception:
                cleanup_failed = exc_info()

            # print(await lr_action.reader.read(20000))
            if cleanup_failed is None:
                return await JSONResponse({
                    "status": "aborted",
                    "exception": {
                        "type":    exc_inf[0].__name__,
                        "message": str(exc_inf[1]),
                        "trace ":  format_tb(exc_inf[2])
                        },
                    "cleanup failed": None
                    })(scope, recieve, send)
            else:
                return await JSONResponse({
                    "status": "aborted",
                    "exception": {
                        "type":    exc_inf[0].__name__,
                        "message": str(exc_inf[1]),
                        "trace ":  format_tb(exc_inf[2])
                        },
                    "cleanup failed": {
                        "type":    cleanup_failed[0].__name__,
                        "message": str(cleanup_failed[1]),
                        "trace ":  format_tb(cleanup_failed[2])
                        }
                    })(scope, recieve, send)
        
        return await JSONResponse(
                        {"status": "OK", "result": ret_dict},
                        background=task
                        )(scope, recieve, send)


