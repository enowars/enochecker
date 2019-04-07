#!/usr/bin/env python3
#from src.enochecker import *
from src.enochecker import *


class ExampleChecker(BaseChecker):
    """
    Change the methods given here, then simply create the class and .run() it.
    Magic.

    A few convenient methods and helpers are provided in the BaseChecker.
    ensure_bytes ans ensure_unicode to make sure strings are always equal.

    As well as methods:
    self.connect() connects to the remote server.
    self.get and self.post request from http.
    self.team_db is a dict that stores its contents to filesystem. (call .persist() to make sure)
    self.readline_expect(): fails if it's not read correctly

    To read the whole docu and find more goodies, run python -m pydoc enochecker
    (Or read the source, Luke)
    """

    def putflag(self):  # type: () -> None
        """
            This method stores a flag in the service.
            In case multiple flags are provided, self.call_idx gives the appropriate index.
            The flag itself can be retrieved from self.flag.
            On error, raise an Eno Exception.
            :raises EnoException on error
            :return this function can return a result if it wants
                    if nothing is returned, the service status is considered okay.
                    the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        if self.call_idx == 0:
            self.team_db[sha256ify(self.flag)] = self.flag
        elif self.call_idx == 1:
            self.global_db["{}_{}".format(self.address, self.flag)] = "Different place for different flag_idx"
        else:
            raise ValueError("Call_Idx {} exceeds the amount of flags. Not supported.".format(self.call_idx))

    def getflag(self):  # type: () -> None
        """
        This method retrieves a flag from the service.
        Use self.flag to get the flag that needs to be recovered and self.roudn to get the round the flag was placed in.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        if self.call_idx == 0:
            if not self.team_db.get(sha256ify(self.flag), None) == self.flag:
                raise BrokenServiceException("We did not get flag 0 back :/")
        elif self.call_idx == 1:
            if not self.global_db.get("{}_{}".format(self.address, self.flag), None) == "Different place for " \
                                                                                        "different flag_idx":
                raise BrokenServiceException("Flag 2 was missing. Service is broken.")
        else:
            raise ValueError("Call_idx {} not supported!".format(self.call_idx))  # Internal error.

    def putnoise(self):  # type: () -> None
        """
        This method stores noise in the service. The noise should later be recoverable.
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using self.call_idx.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        self.team_db["noise"] = self.noise

    def getnoise(self):  # type: () -> None
        """
        This method retrieves noise in the service.
        The noise to be retrieved is inside self.flag
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using call_idx.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        try:
            assert_equals(self.team_db["noise"], self.noise)
        except KeyError:
            raise BrokenServiceException("Noise not found!")

    def havoc(self):  # type: () -> None
        """
        This method unleashes havoc on the app -> Do whatever you must to prove the service still works. Or not.
        On error, raise an EnoException.
        :raises EnoException on Error
        :return This function can return a result if it wants
                If nothing is returned, the service status is considered okay.
                The preferred way to report Errors in the service is by raising an appropriate EnoException
        """
        self.info("I wanted to inform you: I'm  running <3")
        self.http_get("/")  # This will probably fail fail, depending on what params you give the script. :)


app = ExampleChecker.service  # This can be used for uswgi.
if __name__ == "__main__":
    run(ExampleChecker)
    # Example params could be: [StoreFlag localhost ENOFLAG 1 ENOFLAG 50 1]
    # exit(ExampleChecker(port=1337).run())
