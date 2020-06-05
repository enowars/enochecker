Writing the checker
*******************
For a simple checker, subclass :class:`~enochecker.enochecker.BaseChecker`

.. code-block:: py

    from enochecker import BaseChecker, BrokenServiceException, run

    class AwesomeChecker(BaseChecker):
        flag_count = 2
        noise_count = 1
        havoc_count = 1


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

The :func:`~enochecker.enochecker.BaseChecker.putflag` and :func:`~enochecker.enochecker.BaseChecker.getflag` functions should store and retrieve a flag from your service respectively.

The current flag is made available through the ``self.flag`` instance variable.
If you wish to place more than one flag per round in different places, the content of ``self.flag_idx`` tells you which flag you should deploy, starting with `0`.
In that case you should match the value of the variable in the :func:`~enochecker.enochecker.BaseChecker.putflag` and :func:`~enochecker.enochecker.BaseChecker.getflag` functions and act accordingly.
You can communicate the number of flags you want to store per round to the game engine by setting the class variable ``flag_count``.

The noise, which is stored/retrieved using the :func:`~enochecker.enochecker.BaseChecker.putnoise` and :func:`~enochecker.enochecker.BaseChecker.getnoise` functions, is similar to the flag.
Your checker should store/retrieve noise to check that the services is still working as intended.
Unlike the flag, the noise does not need to remain secret, so you could for example post it on a publicly accessible comment section (provided your service has such functionality) to ensure this still works as intended.
You can communicate the number of noises you want to store per round to the game engine by setting the class variable ``noise_count``.

The :func:`~enochecker.enochecker.BaseChecker.havoc` function is intended to check the functionality of those parts of the service which is not covered by the flag and noise functionality.
You can communicate the number of havoc calls you want to receive per round to the game engine by setting the class variable ``havoc_count``.

Communicating the service status
================================
To tell the game engine about the status of the service under check, you can raise various exceptions during the execution of your functions.
If the execution of the function finishes without any exception, it is assumed the status of the service is ok.

In case the service appears to be offline, for example because your connection times out, you should raise a :class:`~enochecker.results.OfflineException`.

In case the service is online but is not working as intended, for example because it responds with unexpected contents or the flag is missing, you should raise a :class:`~enochecker.results.BrokenServiceException`.

If the function raises any other exceptions, this results in the `CHECKER BROKEN` status on the scoreboard.
This should usually never happen, so make sure to catch all exceptions the functions you use might raise.

Persisting data across executions
=================================
Usually you need to store some information when storing the flag that is needed later.
This could be something like usernames and passwords which are necessary to access the flag.
There are multiple storage backends (at the moment :class:`~enochecker.storeddict.StoredDict` and :class:`~enochecker.nosqldict.NoSqlDict`) that are accessible through a common interface.

The ``self.team_db`` dictionary is persisted across restarts.
A good key for storing your information is usually the flag itself, since you want to access the information you stored during the :func:`~enochecker.enochecker.BaseChecker.putflag` call during a later :func:`~enochecker.enochecker.BaseChecker.getflag` call with the same flag in ``self.flag``.
An example for using the ``self.team_db``:

.. code-block:: py

    import secrets

    [...]

    class AwesomeChecker(BaseChecker):
        def putflag(self):
            username = secrets.token_hex(8)
            password = secrets.token_hex(8)
            self.team_db[self.flag] = {
                "username": username,
                "password": password,
            }
            [... register with the generated credentials and store the flag ...]

        def getflag(self):
            if self.flag not in self.team_db or "username" not in self.team_db[self.flag] or "password" not in self.team_db[self.flag]:
                raise BrokenServiceException("storing the corresponding flag was unsuccessful")
            username = self.team_db[self.flag]["username"]
            password = self.team_db[self.flag]["password"]
            [... register with the retrieved credentials and get the flag ...]

HTTP/Telnet Connections
=======================
TODO
