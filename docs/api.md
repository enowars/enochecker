# enochecker.enochecker

## parse_args
```python
parse_args(argv=None)
```

Returns the parsed argparser args.
Args look like this:
[
    "StoreFlag|RetrieveFlag|StoreNoise|RetrieveNoise|Havoc", [Task type]
    "$Address", [Address, either IP or domain]
    "$TeamName",
    "$Round",
    "$Flag|$Noise",
    "$MaxRunningTime",
    "$CallIdx" [index of this task (for each type) in the current round]
]
:param argv: argv. Custom argvs. Will default to sys.argv if not provided.
:return: args object

## BaseChecker
```python
BaseChecker(self, method=None, address=None, team_name=None, round=None, flag=None, call_idx=None, max_time=None, port=None, storage_dir='C:\\Users\\DMaier\\tmp\\enochecker\\src\\.data', from_args=True)
```

All you base are belong to us. Also all your flags. And checker scripts.
Override the methods given here, then simply init and .run().
Magic.

### global_db

A global storage shared between all teams and rounds.
Subsequent calls will return the same db.
Prefer db_team_local or db_round_local
:return: The global db

### http_useragent

The useragent for http(s) requests
:return: the current useragent

### noise

Pretty similar to a flag, just in a different mode (storeNoise vs storeFlag)
:return: The noise

### team_db

The database for the current team
:return: The team local db

### run
```python
BaseChecker.run(self, method=None)
```

Executes the checker and catches errors along the way.
:param method: When calling run, you may call a different method than the one passed on Checker creation
                using this optional param.
:return: the Result code as int, as per the Result enum.

### putflag
```python
BaseChecker.putflag(self)
```

This method stores a flag in the service.
In case multiple flags are provided, self.call_idx gives the appropriate index.
The flag itself can be retrieved from self.flag.
On error, raise an Eno Exception.
:raises EnoException on error
:return this function can return a result if it wants
        if nothing is returned, the service status is considered okay.
        the preferred way to report errors in the service is by raising an appropriate enoexception

### getflag
```python
BaseChecker.getflag(self)
```

This method retrieves a flag from the service.
Use self.flag to get the flag that needs to be recovered and self.roudn to get the round the flag was placed in.
On error, raise an EnoException.
:raises EnoException on error
:return this function can return a result if it wants
        if nothing is returned, the service status is considered okay.
        the preferred way to report errors in the service is by raising an appropriate enoexception

### putnoise
```python
BaseChecker.putnoise(self)
```

This method stores noise in the service. The noise should later be recoverable.
The difference between noise and flag is, tht noise does not have to remain secret for other teams.
This method can be called many times per round. Check how often using self.call_idx.
On error, raise an EnoException.
:raises EnoException on error
:return this function can return a result if it wants
        if nothing is returned, the service status is considered okay.
        the preferred way to report errors in the service is by raising an appropriate enoexception

### getnoise
```python
BaseChecker.getnoise(self)
```

This method retrieves noise in the service.
The noise to be retrieved is inside self.flag
The difference between noise and flag is, tht noise does not have to remain secret for other teams.
This method can be called many times per round. Check how often using call_idx.
On error, raise an EnoException.
:raises EnoException on error
:return this function can return a result if it wants
        if nothing is returned, the service status is considered okay.
        the preferred way to report errors in the service is by raising an appropriate enoexception

### havoc
```python
BaseChecker.havoc(self)
```

This method unleashes havoc on the app -> Do whatever you must to prove the service still works. Or not.
On error, raise an EnoException.
:raises EnoException on Error
:return This function can return a result if it wants
        If nothing is returned, the service status is considered okay.
        The preferred way to report Errors in the service is by raising an appropriate EnoException

### db
```python
BaseChecker.db(self, name, ignore_locks=False)
```

Get a (global) db by name
Subsequent calls will return the same db.
Names can be anything, for example the team name, round numbers etc.
:param name: The name of the DB
:param ignore_locks: Should only be set if you're sure-ish keys are never shared between instances.
        Manual locking ist still possible.
:return: A dict that will be self storing. Alternatively,

### get_team_db
```python
BaseChecker.get_team_db(self, team=None)
```

Returns the database for a specific team.
Subsequent calls will return the same db.
:param team: Return a db for an other team. If none, the db for the local team will be returned.
:return: The team local db

### connect
```python
BaseChecker.connect(self, host=None, port=None, timeout=None)
```

Opens a socket/telnet connection to the remote host.
Use connect(..).get_socket() for the raw socket.
:param host: the host to connect to (defaults to self.address)
:param port: the port to connect to (defaults to self.port)
:param timeout: timeout on connection (defaults to self.max_time)
:return: A connected Telnet instance

### http_useragent_randomize
```python
BaseChecker.http_useragent_randomize(self)
```

Choses a new random http useragent.
Note that http requests will be initialized with a random user agent already.
To retrieve a random useragent without setting it, use random instead.
:return: the new useragent

### http_post
```python
BaseChecker.http_post(self, route='/', params=None, port=None, scheme='http', raise_http_errors=False, timeout=None, **kwargs)
```

Performs a (http) requests.post to the current host.
Caches cookies in self.http_session
:param params: The parameter
:param route: The route
:param port: The remote port in case it has not been specified at creation
:param scheme: The scheme (defaults to http)
:param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
:param timeout: How long we'll try to connect
:return: The response

### http_get
```python
BaseChecker.http_get(self, route='/', params=None, port=None, scheme='http', raise_http_errors=False, timeout=None, **kwargs)
```

Performs a (http) requests.get to the current host.
Caches cookies in self.http_session
:param params: The parameter
:param route: The route
:param port: The remote port in case it has not been specified at creation
:param scheme: The scheme (defaults to http)
:param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
:param timeout: How long we'll try to connect
:return: The response

### http
```python
BaseChecker.http(self, method, route='/', params=None, port=None, scheme='http', raise_http_errors=False, timeout=None, **kwargs)
```

Performs an http request (requests lib) to the current host.
Caches cookies in self.http_session
:param method: The request method
:param params: The parameter
:param route: The route
:param port: The remote port in case it has not been specified at creation
:param scheme: The scheme (defaults to http)
:param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
:param timeout: How long we'll try to connect (default: self.max_time)
:return: The response

## run
```python
run(checker, args=None)
```

__Runs a checker, either from cmdline or as uwsgi script.__

:param checker: The checker (subclass of basechecker) to run
:param force_service: if True (non-default), the server will skip arg parsing and immediately spawn the web service.
:param args: optional parameter, providing parameters
:return:  Never returns.

# enochecker.utils

## assert_in
```python
assert_in(o1, o2, message=None)
```

Raises an exception if o1 not in o2
:param o1: the object that should be in o2
:param o2: the object to look in
:param message: An optional message that will be part of the error

## assert_equals
```python
assert_equals(o1, o2, message=None, autobyteify=False)
```

Raises an exception if o1 != o2
:param o1: the first object
:param o2: the second object
:param message: The exception message in case of an error (optional)
:param autobyteify: will call ensure_bytes on both parameters.

## ensure_bytes
```python
ensure_bytes(obj)
```
Converts to bytes
## ensure_unicode
```python
ensure_unicode(obj)
```
Converts to utf-8
## ensure_valid_filename
```python
ensure_valid_filename(s, min_length=3)
```

Gets a valid file name from the input
:param s: The input string
:param min_length: if the result is smaller than this, the method will fall back to base64.
:return: all illegal chars stripped or base64ified if it gets too small

## snake_caseify
```python
snake_caseify(camel)
```

Turn camels into snake (-cases)
:param camel: camelOrSnakeWhatever
:return: camel_or_snake_whatever

## sha256ify
```python
sha256ify(s)
```

Calculate the sha256 hash
:param s: the string
:return: the hash in hex representation

## base64ify
```python
base64ify(s)
```

Calculate the base64 representation of a value
:param s: the input string
:return: base64 representation

## debase64ify
```python
debase64ify(s)
```

Return a string out of a base64
:param s: the string
:return: the original value

## readline_expect
```python
readline_expect(telnet, expected, read_until='\n', timeout=30)
```

Reads to newline (or read_until string) and assert the presence of a string in the response.
Will raise an exception if failed.
:param telnet: Connected telnet instance (the result of self.telnet(..))
:param expected: the expected String to search for in the response
:param read_until: Which char to read until.
:param timeout: a timeout
:return read: the bytes read

## start_daemon
```python
start_daemon(target)
```

starts a thread as daemon
:param target: the function
:return: the started thread

## serve_once
```python
serve_once(html, start_port=5000, autoincrement_port=True, content_type='text/html', headers=None)
```

Render Text in the users browser
Opens a web server that serves a HTML string once and shuts down after the first request.
The port will be open when this function returns. (though serving the request may take a few mils)
:param html: The html code to deliver on the initial request
:param start_port: The port it should try to listen on first.
:param autoincrement_port: If the port should be increased if the server cannot listen on the provided start_port
:param content_type: The content type this server should report (change it if you want json, for example)
:param headers: Additional headers as {header_key: value} dict.
:return: The port the server started listening on

## SimpleSocket
```python
SimpleSocket(self, host=None, port=0, timeout=<object object at 0x000000000303A670>)
```

Telnetlib with some additions.
Read Telnetlib doku for more.

### readline_expect
```python
SimpleSocket.readline_expect(self, expected, read_until='\n', timeout=30)
```

Reads to newline (or read_until string) and assert the presence of a string in the response.
Will raise an exception if failed.
:param read_until: Which parameter to read until
:param expected: the expected String to search for in the response
:param timeout: a timeout
:return read: the bytes read

# enochecker.results

## Result
```python
Result(self, *args, **kwds)
```

Result Values to be returned from a Checker

### ENOWORKS

Result Values to be returned from a Checker

### INTERNAL_ERROR

Result Values to be returned from a Checker

### OFFLINE

Result Values to be returned from a Checker

### OK

Result Values to be returned from a Checker

### is_valid
```python
Result.is_valid(cls, value)
```

Returns if the value is part of this Enum
:param value: the value
:return: True, if value is part of this Enum

## EnoException
```python
EnoException(self)
```

Base error including the Result. Raise a subclass of me once we know what to do.

### result

Result Values to be returned from a Checker

## BrokenServiceException
```python
BrokenServiceException(self)
```

Indicates a broken Service

### result

Result Values to be returned from a Checker

## OfflineException
```python
OfflineException(self)
```

Service was not reachable (at least once) during our checks

### result

Result Values to be returned from a Checker

# enochecker.storeddict

## makedirs
```python
makedirs(path, exist_ok=True)
```

Python2 ready
param path: the path to create
param exist_ok: ignore already existing path and do nothing

## StoredDict
```python
StoredDict(self, base_path='C:\\Users\\DMaier\\tmp\\enochecker\\src\\.data', name='default', persist_secs=3, ignore_locks=False, *args, **kwargs)
```

A dictionary that is filesystem backed.
It will write to disk every few seconds and at exit.
In case python crashes, changes may be gone. :/
Note: Complex won't be tracked.

### lock
```python
StoredDict.lock(self, *args, **kwargs)
```

Waits for a lock
:param key: the key to lock

### mark_dirty
```python
StoredDict.mark_dirty(self, *args, **kwargs)
```

Manually mark an entry as dirty. It will be updated on disk on the next occasion
:param key: the key that needs to be stored
:return: the value contained in the key

### is_locked
```python
StoredDict.is_locked(self, *args, **kwargs)
```

Returns if the key is currently locked by this process
:param key: The key
:return: True if locked by this process, False otherwise

### reload
```python
StoredDict.reload(self, *args, **kwargs)
```

Reloads stored values from disk.
There is usually no reason to call this.
Non persisted changes might be lost.
Only reason would be if another process fiddles with our data concurrently.

### persist
```python
StoredDict.persist(self, *args, **kwargs)
```

Stores all dirty data to disk.
If no data is to be stored, it's basically free to call.

### release
```python
StoredDict.release(self, *args, **kwargs)
```

Release a file lock
:param locked_key: the key we locked

# enochecker.useragents

## random_useragent
```python
random_useragent()
```

Returns a random useragent
:return: A seemingly valid useragent.

