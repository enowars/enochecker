from abc import ABC

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.background import BackgroundTask

from functools import partial


class LR_Action(ABC):

    @abstractmethod
    async def initial_call(**kwargs):
        pass
    
    @abstractmethod
    async def background_call(**kwargs):
        pass


class LR_Handler(Starlette):
    def __init__(self, lr_callables, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for call in lr_callables:

            self.add_route(
                f"/{call.__class__.__name__}",
                partial(self._callwrapper, lr_call=call),
                methods=["POST"]
                )

    async def _callwrapper(request, lr_call=None):
        kwargs = await request.json()

        # initial Call
        (ret_dict, stuff) = await lr_call.initial_call(kwargs)

        # Background Task
        task = BackgroundTask(lr_call.background_call, stuff)
        return JSONResponse(ret_dict, task)



