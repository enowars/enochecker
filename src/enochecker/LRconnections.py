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
        print("ORIG")
        super().__init__(*args, **kwargs)

        print("HALLO")
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
        
        async def bg_task(timeout):  # lr_action: LR_Action, 
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
                        "type":    str(exc_inf[0]),
                        "message": str(exc_inf[1]),
                        "trace ":  format_tb(exc_inf[2])
                        }
                      })

            except Exception:
                exc_inf = exc_info()
                print({
                      "status": "Error",
                      "exception": {
                        "type":    str(exc_inf[0]),
                        "message": str(exc_inf[1]),
                        "trace ":  format_tb(exc_inf[2])
                        }
                      })

            finally:
                await lr_action.cleanup()
                del lr_action

        print(lr_callable)
        print(scope)
        print(recieve)
        print(send)
        print(args)
        print(rkwargs)

        request = Request(scope, recieve)
        kwargs = await request.json()

        lr_action = lr_callable(kwargs)
        # lr_action = None
        try:
            # initial Call
            ret_dict = await wait_for(lr_action.initial_call(), 10)
            
            # Background Task
            task = BackgroundTask(bg_task, 50)

        except Exception:
            await lr_action.cleanup()
            exc_inf = exc_info()
            # print(await lr_action.reader.read(20000))
            return await JSONResponse({
                "status": "aborted",
                "exception": {
                    "type":    str(exc_inf[0]),
                    "message": str(exc_inf[1]),
                    "trace ":  format_tb(exc_inf[2])
                }
                })(scope, recieve, send)
        
        return await JSONResponse(
                        ret_dict,
                        background=task
                        )(scope, recieve, send)



