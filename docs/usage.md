# Checker Guide

I hope you've already read the [README](../README.md), since I'm skipping most the Stuff already mentionend in there.

## The General Framework
Like the README hinted at, the Checker is a Web-Service recieving POST requests by the central Gameserver. 
Based on what json Request it issues your Checker will run the specified Command.
These commands are defined in the CHECKER_METHODS List.

As time of writing they are:
* putflag
* getflag
* putnoise
* getnoise
* havoc

To bind into these methods subclass the BaseChecker and override the necessary methods.
The target who is to be checked, and some adittional data is given by the request.
The request data is made available in the BaseChecker, via the parameter Names.

```python
    def getflag(self):  # type: () -> None
        """
        This method retrieves a flag from the service.
        Use self.flag to get the flag that needs to be recovered and self.round to get the round the flag was placed in.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        if self.flag_idx == 0:
            if not self.team_db.get(sha256ify(self.flag), None) == self.flag:
                raise BrokenServiceException("We did not get flag 0 back :/")
        elif self.flag_idx == 1:
            if not self.global_db.get("{}_{}".format(self.address, self.flag), None) == "Different place for " \
                                                                                        "different flag_idx":
                raise BrokenServiceException("Flag 2 was missing. Service is broken.")
        else:
            raise ValueError("Call_idx {} not supported!".format(self.flag_idx))  # Internal error.
```

In this example `self.flag` an `self.flax_idx` are used to store 2 different Flags in the Service.

In total there are 10 Params given to the Checker, together with their default values:

```python
# The json spec a checker request follows.
spec = [
    Required("method", CHECKER_METHODS),  # method to execute
    Required("address", str),  # address to check
    Optional("runId", int, 0),  # internal ID of this run inside our db
    Optional("team", str, "FakeTeam"),  # the team name
    Optional("round", int, 0),  # which tick we are in
    Optional("roundLength", int, 300),  # the default tick time
    Optional("flag", str, "ENOTESTFLAG"),  # the flag or noise to drop or get
    Optional("flagIndex", int, 0),  # the index of this flag in a given round (starts at 0)
    Optional("timeout", int, 30),  # timeout we have for this run
    Optional("logEndpoint", str, None)  # endpoint to send runs to
]  # type: List[Union[Required, Optional]]
```

In a standard Checker-Run, flag and flagIndex should suffice when using the wrapper defined in the checkerlib, however for some types of services the aditional data might be necessary.


## StoredDict(s)

The checker itself is instanceiated every round again to not store everything in RAM.
StoredDicts are basically wrapper for file Databases in which arbitrary Key-Value pairs can be stored. 
There are two "Databases" by default available through shortcuts.
The team-database as well as a global database.

To be able to retrieve the necessary data between Checker-Runs one it is advisable to use the flag (or some kind of flag derivative like sha256(self.flag)), as the key to necessary data which getflag may need afterwards. Since assignments of these type are always bound to Hard-Drive access, you should make a temporary copy of the retrieved data, in case it is needed more than once.

(In case we move to a real Database this might be changed in the future)

Another thing to remember is that you might not be able store complex kinds of data, some types might be converted to strings in the process.

Despite being not encouraged you can also define global dictionarys outside the BaseChecker subclass, which then be Global Variables across all rounds in case you need it (for keeping track of subprocesses for example).

## RemoteDict(s)
They *kinda* work in the same way as regular StoredDicts, however they are hosted on a external Mongodb.
For that add an Database.ini as seen in the [example database.ini](../example/database.ini).
If either one of HOST, PORT, USER or PASS is not specified it is overloaded by a default value as seen in the `# database init` in  
[nosqlremotedict.py](../src/enochecker/nosqldict.py).

## Checker-Results
The last Important thing a Checker has to do every round is to report back to the central GameServer about how his Run went. In the checkerlib the responses are taken care for you.
This is done by raising Exeptions during runtime.
There are 4 Different Results a check can result in, although the border between some Results might be fuzzy at times.

### OK
If nothing Exceptional happens the checker should just return, optionally with a value of (`0` or `Result.OK`) although this is not necessary.

For everything else raising a Exeption is the way to go, altough as with Result.OK there are Values in the predefined Result-Enum.

### n0t OK

First: In case any Exception not defined by us is raised, the Checker-Run will result in *`CHECKER BROKEN`*, which (obviously) shouldn't happen.
So make sure you properly catch Exception and reraise them properly.

The two other results are *`Mumble`* and *`Offline`* which are respectively raised by `BrokenServiceException` and `OfflineException`.

When using the wrapper defined by the checkerlib, most exceptions should be caught and redirected to those two already, although there could be stuffed we missed.


## other general Checker knowledge (FAQ)

### Dns resolution
Be aware that the Game-engine gets only one IP address from the DNS unless it's specifically taken care of.
If the service has more than one IP address (for example because the service contains two docker containers) the its needed to manually change the IP address.
for example:
```python
  def getflag(self):
	with self.connect(host = 'fd00:1337:{}:abcd::2'.format(self.team_id) ) as telnet:
      if not self.flag == telnet.read_until(b'\n')
		raise BrokenServiceException("Wrong Flag!")
```

### multiple getflag() on the same flag
Keep in mind that on the same flag getflag can be called multiple times.
Especially if the checker has to register a user or similar it might be a good idea to only do it the first time a flag get getflag'ed.
One can accomplish that for example through:
```python
	def putflag(self):
    	# do the putflag stuff
    	# ...
        
        self.team_db[self.flag]['registered'] = False
        
	def getflag(self):
    	if not self.team_db[self.flag]['registered']:
        	# register
            # ...
            self.team_db[self.flag]['registered'] = True
		# do the standart getflag
        # ...
```
