# EnoChecker

This is the checker lib that shall be used by all checkers in ENOWARS3 and ENOWARS4.

For a simple checker, subclass `enochecker.BaseChecker`.
```python
from enochecker import BaseChecker, BrokenServiceException, run

class AwesomeChecker(BaseChecker):

    def putflag(self):  # type: () -> None
        # TODO: Put flag to service
        self.debug("flag is {}".format(self.flag))
        self.http_post("/putflaghere", params={"flag": self.flag})
        # ...

    def getflag(self):  # type: () -> None
        # tTODO: Get the flag.
        if not self.http_get("/getflag") == self.flag:
            raise BrokenServiceException("Ooops, wrong Flag")

    def putnoise(self):
        # put some noise
        with self.connect() as telnet:
            telnet.write(self.noise)

    def getnoise(self):
        with self.connect() as telnet:
            telnet.write("gimmeflag\n")
            telnet.read_expect(self.noise)

    def havoc(self):
        self.http("FUNFUN").text == "FUNFUN"


if __name__ == "__main__":
    run(AwesomeChecker)
```

A full example, including helpful comments, can be found in [examplechecker.py](example/examplechecker.py).

The full documentation (still in progress) is available on [enowars.github.io/enochecker](https://enowars.github.io/enochecker/).

(There is some not yet ported information in the old [docs/usage.md](docs/usage.md).)

## Installation
The latest stable version of the library is available on pip: `pip install enochecker`

To access the development version, the library can be installed using pip/git, like:
`pip install git+https://github.com/enowars/enochecker`

## Launch Checker
The goal is to have checkers launched via uSWGI and the Engine talking to it via http.
For testing, however, you can use the commandline instead:

```
usage: check.py run [-h] [-a ADDRESS] [-n TEAM_NAME] [-r ROUND] [-f FLAG]
                    [-t MAX_TIME] [-i CALL_IDX] [-p [PORT]]
                    {putflag,getflag,putnoise,getnoise,havoc,listen}

positional arguments:
  {putflag,getflag,putnoise,getnoise,havoc,listen}
                        The Method, one of ['putflag', 'getflag', 'putnoise',
                        'getnoise', 'havoc'] or "listen" to start checker
                        service

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        The ip or address of the remote team to check
  -n TEAM_NAME, --team_name TEAM_NAME
                        The teamname of the team to check
  -r ROUND, --round ROUND
                        The round we are in right now
  -f FLAG, --flag FLAG  The Flag, a Fake flag or a Unique ID, depending on the
                        mode
  -t MAX_TIME, --max_time MAX_TIME
                        The maximum amount of time the script has to execute
                        in seconds
  -i CALL_IDX, --call_idx CALL_IDX
                        Unique numerical index per round. Each id only occurs
                        once and is tighly packed, starting with 0. In a
                        service supporting multiple flags, this would be used
                        to decide which flag to place.
  -p [PORT], --port [PORT]
                        The port the checker should attack

````

## Why use it at all?

Many nice features for CTF Checker writing, obviously.
Also, under-the-hood changes on the Engine can be made without any problems.

For further instructions on how to write a checker with this Framework look at [docs/usage.md](docs/usage.md).

Now, code away :).
