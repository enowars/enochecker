# EnoChecker

This is the checker lib that shall be used by all checkers in ENOWARS3.

For a simple checker, subclass `enochecker.BaseChecker`.
```python
class ExampleChecker(BaseChecker):
    def putflag(self):  # type: () -> None
        # TODO: Put flag to service
        self.http_get("/putflaghere")
        # ...
        
    def getflag(self):  # type: () -> None
        # tTODO: Get the flag.
        self.http_post("/dothings")
        
if __name__ == "__main__":
    run(ExampleChecker)
```

A full example, including helpful comments, can be found in [examplechecker.py](examplechecker.py).

The full API specification can be found [docs/api.md](docs/api.md).
(Generated from docstring using `pydocmd simple ...`).
