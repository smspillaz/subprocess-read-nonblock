# subprocess - Subprocesses with accessible I/O streams
#
# For more information about this module, see PEP 324.
#
# Copyright (c) 2003-2005 by Peter Astrand <astrand@lysator.liu.se>
#
# Licensed to PSF under a Contributor Agreement.
# See http://www.python.org/2.4/license for licensing details.

r"""subprocess - Subprocesses with accessible I/O streams

This module allows you to spawn processes, connect to their
input/output/error pipes, and obtain their return codes.  This module
intends to replace several older modules and functions:

os.system
os.spawn*

Information about how the subprocess module can be used to replace these
modules and functions can be found below.



Using the subprocess module
===========================
This module defines one class called Popen:

class Popen(args, bufsize=-1, executable=None,
            stdin=None, stdout=None, stderr=None,
            preexec_fn=None, close_fds=True, shell=False,
            cwd=None, env=None, universal_newlines=False,
            startupinfo=None, creationflags=0,
            restore_signals=True, start_new_session=False, pass_fds=()):


Arguments are:

args should be a string, or a sequence of program arguments.  The
program to execute is normally the first item in the args sequence or
string, but can be explicitly set by using the executable argument.

On POSIX, with shell=False (default): In this case, the Popen class
uses os.execvp() to execute the child program.  args should normally
be a sequence.  A string will be treated as a sequence with the string
as the only item (the program to execute).

On POSIX, with shell=True: If args is a string, it specifies the
command string to execute through the shell.  If args is a sequence,
the first item specifies the command string, and any additional items
will be treated as additional shell arguments.

On Windows: the Popen class uses CreateProcess() to execute the child
program, which operates on strings.  If args is a sequence, it will be
converted to a string using the list2cmdline method.  Please note that
not all MS Windows applications interpret the command line the same
way: The list2cmdline is designed for applications using the same
rules as the MS C runtime.

bufsize will be supplied as the corresponding argument to the io.open()
function when creating the stdin/stdout/stderr pipe file objects:
0 means unbuffered (read & write are one system call and can return short),
1 means line buffered, any other positive value means use a buffer of
approximately that size.  A negative bufsize, the default, means the system
default of io.DEFAULT_BUFFER_SIZE will be used.

stdin, stdout and stderr specify the executed programs' standard
input, standard output and standard error file handles, respectively.
Valid values are PIPE, an existing file descriptor (a positive
integer), an existing file object, and None.  PIPE indicates that a
new pipe to the child should be created.  With None, no redirection
will occur; the child's file handles will be inherited from the
parent.  Additionally, stderr can be STDOUT, which indicates that the
stderr data from the applications should be captured into the same
file handle as for stdout.

On POSIX, if preexec_fn is set to a callable object, this object will be
called in the child process just before the child is executed.  The use
of preexec_fn is not thread safe, using it in the presence of threads
could lead to a deadlock in the child process before the new executable
is executed.

If close_fds is true, all file descriptors except 0, 1 and 2 will be
closed before the child process is executed.  The default for close_fds
varies by platform:  Always true on POSIX.  True when stdin/stdout/stderr
are None on Windows, false otherwise.

pass_fds is an optional sequence of file descriptors to keep open between the
parent and child.  Providing any pass_fds implicitly sets close_fds to true.

if shell is true, the specified command will be executed through the
shell.

If cwd is not None, the current directory will be changed to cwd
before the child is executed.

On POSIX, if restore_signals is True all signals that Python sets to
SIG_IGN are restored to SIG_DFL in the child process before the exec.
Currently this includes the SIGPIPE, SIGXFZ and SIGXFSZ signals.  This
parameter does nothing on Windows.

On POSIX, if start_new_session is True, the setsid() system call will be made
in the child process prior to executing the command.

If env is not None, it defines the environment variables for the new
process.

If universal_newlines is False, the file objects stdin, stdout and stderr
are opened as binary files, and no line ending conversion is done.

If universal_newlines is True, the file objects stdout and stderr are
opened as a text file, but lines may be terminated by any of '\n',
the Unix end-of-line convention, '\r', the old Macintosh convention or
'\r\n', the Windows convention.  All of these external representations
are seen as '\n' by the Python program.  Also, the newlines attribute
of the file objects stdout, stdin and stderr are not updated by the
communicate() method.

In either case, the process being communicated with should start up
expecting to receive bytes on its standard input and decode them with
the same encoding they are sent in.

The startupinfo and creationflags, if given, will be passed to the
underlying CreateProcess() function.  They can specify things such as
appearance of the main window and priority for the new process.
(Windows only)


This module also defines some shortcut functions:

call(*popenargs, **kwargs):
    Run command with arguments.  Wait for command to complete, then
    return the returncode attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> retcode = subprocess.call(["ls", "-l"])

check_call(*popenargs, **kwargs):
    Run command with arguments.  Wait for command to complete.  If the
    exit code was zero then return, otherwise raise
    CalledProcessError.  The CalledProcessError object will have the
    return code in the returncode attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> subprocess.check_call(["ls", "-l"])
    0

getstatusoutput(cmd):
    Return (status, output) of executing cmd in a shell.

    Execute the string 'cmd' in a shell with 'check_output' and
    return a 2-tuple (status, output). Universal newlines mode is used,
    meaning that the result with be decoded to a string.

    A trailing newline is stripped from the output.
    The exit status for the command can be interpreted
    according to the rules for the function 'wait'.  Example:

    >>> subprocess.getstatusoutput('ls /bin/ls')
    (0, '/bin/ls')
    >>> subprocess.getstatusoutput('cat /bin/junk')
    (256, 'cat: /bin/junk: No such file or directory')
    >>> subprocess.getstatusoutput('/bin/junk')
    (256, 'sh: /bin/junk: not found')

getoutput(cmd):
    Return output (stdout or stderr) of executing cmd in a shell.

    Like getstatusoutput(), except the exit status is ignored and the return
    value is a string containing the command's output.  Example:

    >>> subprocess.getoutput('ls /bin/ls')
    '/bin/ls'

check_output(*popenargs, **kwargs):
    Run command with arguments and return its output.

    If the exit code was non-zero it raises a CalledProcessError.  The
    CalledProcessError object will have the return code in the returncode
    attribute and output in the output attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> output = subprocess.check_output(["ls", "-l", "/dev/null"])

    There is an additional optional argument, "input", allowing you to
    pass a string to the subprocess's stdin.  If you use this argument
    you may not also use the Popen constructor's "stdin" argument.

    If universal_newlines is set to True, the "input" argument must
    be a string rather than bytes, and the return value will be a string.

Exceptions
----------
Exceptions raised in the child process, before the new program has
started to execute, will be re-raised in the parent.  Additionally,
the exception object will have one extra attribute called
'child_traceback', which is a string containing traceback information
from the child's point of view.

The most common exception raised is OSError.  This occurs, for
example, when trying to execute a non-existent file.  Applications
should prepare for OSErrors.

A ValueError will be raised if Popen is called with invalid arguments.

Exceptions defined within this module inherit from SubprocessError.
check_call() and check_output() will raise CalledProcessError if the
called process returns a non-zero return code.  TimeoutExpired
be raised if a timeout was specified and expired.


Security
--------
Unlike some other popen functions, this implementation will never call
/bin/sh implicitly.  This means that all characters, including shell
metacharacters, can safely be passed to child processes.


Popen objects
=============
Instances of the Popen class have the following methods:

poll()
    Check if child process has terminated.  Returns returncode
    attribute.

wait()
    Wait for child process to terminate.  Returns returncode attribute.

communicate(input=None)
    Interact with process: Send data to stdin.  Read data from stdout
    and stderr, until end-of-file is reached.  Wait for process to
    terminate.  The optional input argument should be data to be
    sent to the child process, or None, if no data should be sent to
    the child. If the Popen instance was constructed with universal_newlines
    set to True, the input argument should be a string and will be encoded
    using the preferred system encoding (see locale.getpreferredencoding);
    if universal_newlines is False, the input argument should be a
    byte string.

    communicate() returns a tuple (stdout, stderr).

    Note: The data read is buffered in memory, so do not use this
    method if the data size is large or unlimited.

The following attributes are also available:

stdin
    If the stdin argument is PIPE, this attribute is a file object
    that provides input to the child process.  Otherwise, it is None.

stdout
    If the stdout argument is PIPE, this attribute is a file object
    that provides output from the child process.  Otherwise, it is
    None.

stderr
    If the stderr argument is PIPE, this attribute is file object that
    provides error output from the child process.  Otherwise, it is
    None.

pid
    The process ID of the child process.

returncode
    The child return code.  A None value indicates that the process
    hasn't terminated yet.  A negative value -N indicates that the
    child was terminated by signal N (POSIX only).


Replacing older functions with the subprocess module
====================================================
In this section, "a ==> b" means that b can be used as a replacement
for a.

Note: All functions in this section fail (more or less) silently if
the executed program cannot be found; this module raises an OSError
exception.

In the following examples, we assume that the subprocess module is
imported with "from subprocess import *".


Replacing /bin/sh shell backquote
---------------------------------
output=`mycmd myarg`
==>
output = Popen(["mycmd", "myarg"], stdout=PIPE).communicate()[0]


Replacing shell pipe line
-------------------------
output=`dmesg | grep hda`
==>
p1 = Popen(["dmesg"], stdout=PIPE)
p2 = Popen(["grep", "hda"], stdin=p1.stdout, stdout=PIPE)
output = p2.communicate()[0]


Replacing os.system()
---------------------
sts = os.system("mycmd" + " myarg")
==>
p = Popen("mycmd" + " myarg", shell=True)
pid, sts = os.waitpid(p.pid, 0)

Note:

* Calling the program through the shell is usually not required.

* It's easier to look at the returncode attribute than the
  exitstatus.

A more real-world example would look like this:

try:
    retcode = call("mycmd" + " myarg", shell=True)
    if retcode < 0:
        print("Child was terminated by signal", -retcode, file=sys.stderr)
    else:
        print("Child returned", retcode, file=sys.stderr)
except OSError as e:
    print("Execution failed:", e, file=sys.stderr)


Replacing os.spawn*
-------------------
P_NOWAIT example:

pid = os.spawnlp(os.P_NOWAIT, "/bin/mycmd", "mycmd", "myarg")
==>
pid = Popen(["/bin/mycmd", "myarg"]).pid


P_WAIT example:

retcode = os.spawnlp(os.P_WAIT, "/bin/mycmd", "mycmd", "myarg")
==>
retcode = call(["/bin/mycmd", "myarg"])


Vector example:

os.spawnvp(os.P_NOWAIT, path, args)
==>
Popen([path] + args[1:])


Environment example:

os.spawnlpe(os.P_NOWAIT, "/bin/mycmd", "mycmd", "myarg", env)
==>
Popen(["/bin/mycmd", "myarg"], env={"PATH": "/usr/bin"})
"""

import sys
_mswindows = (sys.platform == "win32")

import io
import os
import time
import signal
import builtins
import warnings
import errno
try:
    from time import monotonic as _time
except ImportError:
    from time import time as _time

import math
import select
import sys

import gc

from collections import namedtuple, Mapping

# generic events, that must be mapped to implementation-specific ones
EVENT_READ = (1 << 0)
EVENT_WRITE = (1 << 1)


def _fileobj_to_fd(fileobj):
    """Return a file descriptor from a file object.

    Parameters:
    fileobj -- file object or file descriptor

    Returns:
    corresponding file descriptor

    Raises:
    ValueError if the object is invalid
    """
    if isinstance(fileobj, int):
        fd = fileobj
    else:
        try:
            fd = int(fileobj.fileno())
        except (AttributeError, TypeError, ValueError):
            raise ValueError("Invalid file object: "
                             "{!r}".format(fileobj))
    if fd < 0:
        raise ValueError("Invalid file descriptor: {}".format(fd))
    return fd


SelectorKey = namedtuple('SelectorKey', ['fileobj', 'fd', 'events', 'data'])
"""Object used to associate a file object to its backing file descriptor,
selected event mask and attached data."""


class _SelectorMapping(Mapping):
    """Mapping of file objects to selector keys."""

    def __init__(self, selector):
        self._selector = selector

    def __len__(self):
        return len(self._selector._fd_to_key)

    def __getitem__(self, fileobj):
        try:
            fd = self._selector._fileobj_lookup(fileobj)
            return self._selector._fd_to_key[fd]
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))

    def __iter__(self):
        return iter(self._selector._fd_to_key)


class BaseSelector():
    """Selector abstract base class.

    A selector supports registering file objects to be monitored for specific
    I/O events.

    A file object is a file descriptor or any object with a `fileno()` method.
    An arbitrary object can be attached to the file object, which can be used
    for example to store context information, a callback, etc.

    A selector can use various implementations (select(), poll(), epoll()...)
    depending on the platform. The default `Selector` class uses the most
    efficient implementation on the current platform.
    """

    def register(self, fileobj, events, data=None):
        """Register a file object.

        Parameters:
        fileobj -- file object or file descriptor
        events  -- events to monitor (bitwise mask of EVENT_READ|EVENT_WRITE)
        data    -- attached data

        Returns:
        SelectorKey instance

        Raises:
        ValueError if events is invalid
        KeyError if fileobj is already registered
        OSError if fileobj is closed or otherwise is unacceptable to
                the underlying system call (if a system call is made)

        Note:
        OSError may or may not be raised
        """
        raise NotImplementedError

    def unregister(self, fileobj):
        """Unregister a file object.

        Parameters:
        fileobj -- file object or file descriptor

        Returns:
        SelectorKey instance

        Raises:
        KeyError if fileobj is not registered

        Note:
        If fileobj is registered but has since been closed this does
        *not* raise OSError (even if the wrapped syscall does)
        """
        raise NotImplementedError

    def modify(self, fileobj, events, data=None):
        """Change a registered file object monitored events or attached data.

        Parameters:
        fileobj -- file object or file descriptor
        events  -- events to monitor (bitwise mask of EVENT_READ|EVENT_WRITE)
        data    -- attached data

        Returns:
        SelectorKey instance

        Raises:
        Anything that unregister() or register() raises
        """
        self.unregister(fileobj)
        return self.register(fileobj, events, data)

    def select(self, timeout=None):
        """Perform the actual selection, until some monitored file objects are
        ready or a timeout expires.

        Parameters:
        timeout -- if timeout > 0, this specifies the maximum wait time, in
                   seconds
                   if timeout <= 0, the select() call won't block, and will
                   report the currently ready file objects
                   if timeout is None, select() will block until a monitored
                   file object becomes ready

        Returns:
        list of (key, events) for ready file objects
        `events` is a bitwise mask of EVENT_READ|EVENT_WRITE
        """
        raise NotImplementedError

    def close(self):
        """Close the selector.

        This must be called to make sure that any underlying resource is freed.
        """
        pass

    def get_key(self, fileobj):
        """Return the key associated to a registered file object.

        Returns:
        SelectorKey for this file object
        """
        mapping = self.get_map()
        if mapping is None:
            raise RuntimeError('Selector is closed')
        try:
            return mapping[fileobj]
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))

    def get_map(self):
        """Return a mapping of file objects to selector keys."""
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _BaseSelectorImpl(BaseSelector):
    """Base selector implementation."""

    def __init__(self):
        # this maps file descriptors to keys
        self._fd_to_key = {}
        # read-only mapping returned by get_map()
        self._map = _SelectorMapping(self)

    def _fileobj_lookup(self, fileobj):
        """Return a file descriptor from a file object.

        This wraps _fileobj_to_fd() to do an exhaustive search in case
        the object is invalid but we still have it in our map.  This
        is used by unregister() so we can unregister an object that
        was previously registered even if it is closed.  It is also
        used by _SelectorMapping.
        """
        try:
            return _fileobj_to_fd(fileobj)
        except ValueError:
            # Do an exhaustive search.
            for key in self._fd_to_key.values():
                if key.fileobj is fileobj:
                    return key.fd
            # Raise ValueError after all.
            raise

    def register(self, fileobj, events, data=None):
        if (not events) or (events & ~(EVENT_READ | EVENT_WRITE)):
            raise ValueError("Invalid events: {!r}".format(events))

        key = SelectorKey(fileobj, self._fileobj_lookup(fileobj), events, data)

        if key.fd in self._fd_to_key:
            raise KeyError("{!r} (FD {}) is already registered"
                           .format(fileobj, key.fd))

        self._fd_to_key[key.fd] = key
        return key

    def unregister(self, fileobj):
        try:
            key = self._fd_to_key.pop(self._fileobj_lookup(fileobj))
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))
        return key

    def modify(self, fileobj, events, data=None):
        # TODO: Subclasses can probably optimize this even further.
        try:
            key = self._fd_to_key[self._fileobj_lookup(fileobj)]
        except KeyError:
            raise KeyError("{!r} is not registered".format(fileobj))
        if events != key.events:
            self.unregister(fileobj)
            key = self.register(fileobj, events, data)
        elif data != key.data:
            # Use a shortcut to update the data.
            key = key._replace(data=data)
            self._fd_to_key[key.fd] = key
        return key

    def close(self):
        self._fd_to_key.clear()
        self._map = None

    def get_map(self):
        return self._map

    def _key_from_fd(self, fd):
        """Return the key associated to a given file descriptor.

        Parameters:
        fd -- file descriptor

        Returns:
        corresponding key, or None if not found
        """
        try:
            return self._fd_to_key[fd]
        except KeyError:
            return None

class SelectSelector(_BaseSelectorImpl):
    """Select-based selector."""

    def __init__(self):
        _BaseSelectorImpl.__init__(self)
        self._readers = set()
        self._writers = set()

    def register(self, fileobj, events, data=None):
        key = _BaseSelectorImpl.register(self, fileobj, events, data)
        if events & EVENT_READ:
            self._readers.add(key.fd)
        if events & EVENT_WRITE:
            self._writers.add(key.fd)
        return key

    def unregister(self, fileobj):
        key = _BaseSelectorImpl.unregister(self, fileobj)
        self._readers.discard(key.fd)
        self._writers.discard(key.fd)
        return key

    if sys.platform == 'win32':
        def _select(self, r, w, _, timeout=None):
            r, w, x = select.select(r, w, w, timeout)
            return r, w + x, []
    else:
        _select = select.select

    def select(self, timeout=None):
        timeout = None if timeout is None else max(timeout, 0)
        ready = []
        try:
            r, w, _ = self._select(self._readers, self._writers, [], timeout)
        except InterruptedError:
            return ready
        r = set(r)
        w = set(w)
        for fd in r | w:
            events = 0
            if fd in r:
                events |= EVENT_READ
            if fd in w:
                events |= EVENT_WRITE

            key = self._key_from_fd(fd)
            if key:
                ready.append((key, events & key.events))
        return ready


if hasattr(select, 'poll'):

    class PollSelector(_BaseSelectorImpl):
        """Poll-based selector."""

        def __init__(self):
            _BaseSelectorImpl.__init__(self)
            self._poll = select.poll()

        def register(self, fileobj, events, data=None):
            key = _BaseSelectorImpl.register(self, fileobj, events, data)
            poll_events = 0
            if events & EVENT_READ:
                poll_events |= select.POLLIN
            if events & EVENT_WRITE:
                poll_events |= select.POLLOUT
            self._poll.register(key.fd, poll_events)
            return key

        def unregister(self, fileobj):
            key = _BaseSelectorImpl.unregister(self, fileobj)
            self._poll.unregister(key.fd)
            return key

        def select(self, timeout=None):
            if timeout is None:
                timeout = None
            elif timeout <= 0:
                timeout = 0
            else:
                # poll() has a resolution of 1 millisecond, round away from
                # zero to wait *at least* timeout seconds.
                timeout = math.ceil(timeout * 1e3)
            ready = []
            try:
                fd_event_list = self._poll.poll(timeout)
            except InterruptedError:
                return ready
            for fd, event in fd_event_list:
                events = 0
                if event & ~select.POLLIN:
                    events |= EVENT_WRITE
                if event & ~select.POLLOUT:
                    events |= EVENT_READ

                key = self._key_from_fd(fd)
                if key:
                    ready.append((key, events & key.events))
            return ready

else:

    PollSelector = None

# Exception classes used by this module.
class SubprocessError(Exception): pass


class CalledProcessError(SubprocessError):
    """This exception is raised when a process run by check_call() or
    check_output() returns a non-zero exit status.
    The exit status will be stored in the returncode attribute;
    check_output() will also store the output in the output attribute.
    """
    def __init__(self, returncode, cmd, output=None, stderr=None):
        self.returncode = returncode
        self.cmd = cmd
        self.output = output
        self.stderr = stderr

    def __str__(self):
        return "Command '%s' returned non-zero exit status %d" % (self.cmd, self.returncode)

    @property
    def stdout(self):
        """Alias for output attribute, to match stderr"""
        return self.output

    @stdout.setter
    def stdout(self, value):
        # There's no obvious reason to set this, but allow it anyway so
        # .stdout is a transparent alias for .output
        self.output = value


class TimeoutExpired(SubprocessError):
    """This exception is raised when the timeout expires while waiting for a
    child process.
    """
    def __init__(self, cmd, timeout, output=None, stderr=None):
        self.cmd = cmd
        self.timeout = timeout
        self.output = output
        self.stderr = stderr

    def __str__(self):
        return ("Command '%s' timed out after %s seconds" %
                (self.cmd, self.timeout))

    @property
    def stdout(self):
        return self.output

    @stdout.setter
    def stdout(self, value):
        # There's no obvious reason to set this, but allow it anyway so
        # .stdout is a transparent alias for .output
        self.output = value


if _mswindows:
    from collections import namedtuple
    import itertools
    import locale
    import _overlapped
    import tempfile
    import threading
    import msvcrt
    import _winapi

    class STARTUPINFO:
        dwFlags = 0
        hStdInput = None
        hStdOutput = None
        hStdError = None
        wShowWindow = 0
    _OverlappedIO = namedtuple('_OverlappedIO', 'name io event')
else:
    import fcntl
    import select
    try:
        import threading
    except ImportError:
        import dummy_threading as threading

    _has_poll = hasattr(select, 'poll')
    import fcntl
    import pickle

    try:
        import _posixsubprocess
    except ImportError:
        _posixsubprocess = None
        warnings.warn("The _posixsubprocess module is not being used. "
                      "Child process reliability may suffer if your "
                      "program uses threads.", RuntimeWarning)

    # When select or poll has indicated that the file is writable,
    # we can write up to _PIPE_BUF bytes without risk of blocking.
    # POSIX defines PIPE_BUF as >= 512.
    _PIPE_BUF = getattr(select, 'PIPE_BUF', 512)

    # poll/select have the advantage of not requiring any extra file
    # descriptor, contrarily to epoll/kqueue (also, they require a single
    # syscall).
    if PollSelector:
        _PopenSelector = PollSelector
    else:
        _PopenSelector = SelectSelector

    _FD_CLOEXEC = getattr(fcntl, 'FD_CLOEXEC', 1)

    def _set_cloexec(fd, cloexec):
        old = fcntl.fcntl(fd, fcntl.F_GETFD)
        if cloexec:
            fcntl.fcntl(fd, fcntl.F_SETFD, old | _FD_CLOEXEC)
        else:
            fcntl.fcntl(fd, fcntl.F_SETFD, old & ~_FD_CLOEXEC)

    if _posixsubprocess:
        _create_pipe = _posixsubprocess.cloexec_pipe
    else:
        def _create_pipe():
            fds = os.pipe()
            _set_cloexec(fds[0], True)
            _set_cloexec(fds[1], True)
            return fds

__all__ = ["Popen", "PIPE", "STDOUT", "call", "check_call", "getstatusoutput",
           "getoutput", "check_output", "run", "CalledProcessError", "DEVNULL",
           "SubprocessError", "TimeoutExpired", "CompletedProcess"]
           # NOTE: We intentionally exclude list2cmdline as it is
           # considered an internal implementation detail.  issue10838.

if _mswindows:
    from _winapi import (CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP,
                         STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
                         STD_ERROR_HANDLE, SW_HIDE,
                         STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW)

    __all__.extend(["CREATE_NEW_CONSOLE", "CREATE_NEW_PROCESS_GROUP",
                    "STD_INPUT_HANDLE", "STD_OUTPUT_HANDLE",
                    "STD_ERROR_HANDLE", "SW_HIDE",
                    "STARTF_USESTDHANDLES", "STARTF_USESHOWWINDOW"])

    class Handle(int):
        closed = False

        def Close(self, CloseHandle=_winapi.CloseHandle):
            if not self.closed:
                self.closed = True
                CloseHandle(self)

        def Detach(self):
            if not self.closed:
                self.closed = True
                return int(self)
            raise ValueError("already closed")

        def __repr__(self):
            return "Handle(%d)" % int(self)

        __del__ = Close
        __str__ = __repr__

    _WAIT = 0xffffffff
    BUFSIZE = 8192
    _mmap_counter = itertools.count()
    # Replacement for os.pipe() using handles instead of fds, originally lived
    # in asyncio/windows_utils.py, but used here due to circular import
    # prevention.
    def _pipe(duplex=False, overlapped=(True, True), bufsize=BUFSIZE):
        """Like os.pipe() but with overlapped support and using handles not fds."""
        address = tempfile.mktemp(prefix=r'\\.\pipe\python-pipe-%d-%d-' %
                                  (os.getpid(), next(_mmap_counter)))

        if duplex:
            openmode = _winapi.PIPE_ACCESS_DUPLEX
            access = _winapi.GENERIC_READ | _winapi.GENERIC_WRITE
            obsize, ibsize = bufsize, bufsize
        else:
            openmode = _winapi.PIPE_ACCESS_INBOUND
            access = _winapi.GENERIC_WRITE
            obsize, ibsize = 0, bufsize

        openmode |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE

        if overlapped[0]:
            openmode |= _winapi.FILE_FLAG_OVERLAPPED

        if overlapped[1]:
            flags_and_attribs = _winapi.FILE_FLAG_OVERLAPPED
        else:
            flags_and_attribs = 0

        h1 = h2 = None
        try:
            h1 = _winapi.CreateNamedPipe(
                address, openmode, _winapi.PIPE_WAIT,
                1, obsize, ibsize, _winapi.NMPWAIT_WAIT_FOREVER, _winapi.NULL)

            h2 = _winapi.CreateFile(
                address, access, 0, _winapi.NULL, _winapi.OPEN_EXISTING,
                flags_and_attribs, _winapi.NULL)

            ov = _winapi.ConnectNamedPipe(h1, overlapped=True)
            ov.GetOverlappedResult(True)
            return h1, h2
        except:
            if h1 is not None:
                _winapi.CloseHandle(h1)
            if h2 is not None:
                _winapi.CloseHandle(h2)
            raise

try:
    MAXFD = os.sysconf("SC_OPEN_MAX")
except:
    MAXFD = 256

_READ_BLOCK_SIZE = 32768

# This lists holds Popen instances for which the underlying process had not
# exited at the time its __del__ method got called: those processes are wait()ed
# for synchronously from _cleanup() when a new Popen object is created, to avoid
# zombie processes.
_active = []

def _cleanup():
    for inst in _active[:]:
        res = inst._internal_poll(_deadstate=sys.maxsize)
        if res is not None:
            try:
                _active.remove(inst)
            except ValueError:
                # This can happen if two threads create a new Popen instance.
                # It's harmless that it was already removed, so ignore.
                pass

PIPE = -1
STDOUT = -2
DEVNULL = -3


def _eintr_retry_call(func, *args):
    while True:
        try:
            return func(*args)
        except InterruptedError:
            continue


# XXX This function is only used by multiprocessing and the test suite,
# but it's here so that it can be imported when Python is compiled without
# threads.

def _args_from_interpreter_flags():
    """Return a list of command-line arguments reproducing the current
    settings in sys.flags and sys.warnoptions."""
    flag_opt_map = {
        'debug': 'd',
        # 'inspect': 'i',
        # 'interactive': 'i',
        'optimize': 'O',
        'dont_write_bytecode': 'B',
        'no_user_site': 's',
        'no_site': 'S',
        'ignore_environment': 'E',
        'verbose': 'v',
        'bytes_warning': 'b',
        'quiet': 'q',
        'hash_randomization': 'R',
    }
    args = []
    for flag, opt in flag_opt_map.items():
        v = getattr(sys.flags, flag)
        if v > 0:
            if flag == 'hash_randomization':
                v = 1 # Handle specification of an exact seed
            args.append('-' + opt * v)
    for opt in sys.warnoptions:
        args.append('-W' + opt)
    return args


def call(timeout=None, *popenargs, **kwargs):
    """Run command with arguments.  Wait for command to complete or
    timeout, then return the returncode attribute.

    The arguments are the same as for the Popen constructor.  Example:

    retcode = call(["ls", "-l"])
    """
    with Popen(*popenargs, **kwargs) as p:
        try:
            return p.wait(timeout=timeout)
        except:
            p.kill()
            p.wait()
            raise


def check_call(*popenargs, **kwargs):
    """Run command with arguments.  Wait for command to complete.  If
    the exit code was zero then return, otherwise raise
    CalledProcessError.  The CalledProcessError object will have the
    return code in the returncode attribute.

    The arguments are the same as for the call function.  Example:

    check_call(["ls", "-l"])
    """
    retcode = call(*popenargs, **kwargs)
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise CalledProcessError(retcode, cmd)
    return 0


def check_output(timeout=None, *popenargs, **kwargs):
    r"""Run command with arguments and return its output.

    If the exit code was non-zero it raises a CalledProcessError.  The
    CalledProcessError object will have the return code in the returncode
    attribute and output in the output attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> check_output(["ls", "-l", "/dev/null"])
    b'crw-rw-rw- 1 root root 1, 3 Oct 18  2007 /dev/null\n'

    The stdout argument is not allowed as it is used internally.
    To capture standard error in the result, use stderr=STDOUT.

    >>> check_output(["/bin/sh", "-c",
    ...               "ls -l non_existent_file ; exit 0"],
    ...              stderr=STDOUT)
    b'ls: non_existent_file: No such file or directory\n'

    There is an additional optional argument, "input", allowing you to
    pass a string to the subprocess's stdin.  If you use this argument
    you may not also use the Popen constructor's "stdin" argument, as
    it too will be used internally.  Example:

    >>> check_output(["sed", "-e", "s/foo/bar/"],
    ...              input=b"when in the course of fooman events\n")
    b'when in the course of barman events\n'

    If universal_newlines=True is passed, the "input" argument must be a
    string and the return value will be a string rather than bytes.
    """
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')

    if 'input' in kwargs and kwargs['input'] is None:
        # Explicitly passing input=None was previously equivalent to passing an
        # empty string. That is maintained here for backwards compatibility.
        kwargs['input'] = '' if kwargs.get('universal_newlines', False) else b''

    return run(*popenargs, stdout=PIPE, timeout=timeout, check=True,
               **kwargs).stdout


class CompletedProcess(object):
    """A process that has finished running.

    This is returned by run().

    Attributes:
      args: The list or str args passed to run().
      returncode: The exit code of the process, negative for signals.
      stdout: The standard output (None if not captured).
      stderr: The standard error (None if not captured).
    """
    def __init__(self, args, returncode, stdout=None, stderr=None):
        self.args = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __repr__(self):
        args = ['args={!r}'.format(self.args),
                'returncode={!r}'.format(self.returncode)]
        if self.stdout is not None:
            args.append('stdout={!r}'.format(self.stdout))
        if self.stderr is not None:
            args.append('stderr={!r}'.format(self.stderr))
        return "{}({})".format(type(self).__name__, ', '.join(args))

    def check_returncode(self):
        """Raise CalledProcessError if the exit code is non-zero."""
        if self.returncode:
            raise CalledProcessError(self.returncode, self.args, self.stdout,
                                     self.stderr)


def run(input=None, timeout=None, check=False, *popenargs, **kwargs):
    """Run command with arguments and return a CompletedProcess instance.

    The returned instance will have attributes args, returncode, stdout and
    stderr. By default, stdout and stderr are not captured, and those attributes
    will be None. Pass stdout=PIPE and/or stderr=PIPE in order to capture them.

    If check is True and the exit code was non-zero, it raises a
    CalledProcessError. The CalledProcessError object will have the return code
    in the returncode attribute, and output & stderr attributes if those streams
    were captured.

    If timeout is given, and the process takes too long, a TimeoutExpired
    exception will be raised.

    There is an optional argument "input", allowing you to
    pass a string to the subprocess's stdin.  If you use this argument
    you may not also use the Popen constructor's "stdin" argument, as
    it will be used internally.

    The other arguments are the same as for the Popen constructor.

    If universal_newlines=True is passed, the "input" argument must be a
    string and stdout/stderr in the returned object will be strings rather than
    bytes.
    """
    if input is not None:
        if 'stdin' in kwargs:
            raise ValueError('stdin and input arguments may not both be used.')
        kwargs['stdin'] = PIPE

    with Popen(*popenargs, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise TimeoutExpired(process.args, timeout, output=stdout,
                                 stderr=stderr)
        except:
            process.kill()
            process.wait()
            raise
        retcode = process.poll()
        if check and retcode:
            raise CalledProcessError(retcode, process.args,
                                     output=stdout, stderr=stderr)
    return CompletedProcess(process.args, retcode, stdout, stderr)


def list2cmdline(seq):
    """
    Translate a sequence of arguments into a command line
    string, using the same rules as the MS C runtime:

    1) Arguments are delimited by white space, which is either a
       space or a tab.

    2) A string surrounded by double quotation marks is
       interpreted as a single argument, regardless of white space
       contained within.  A quoted string can be embedded in an
       argument.

    3) A double quotation mark preceded by a backslash is
       interpreted as a literal double quotation mark.

    4) Backslashes are interpreted literally, unless they
       immediately precede a double quotation mark.

    5) If backslashes immediately precede a double quotation mark,
       every pair of backslashes is interpreted as a literal
       backslash.  If the number of backslashes is odd, the last
       backslash escapes the next double quotation mark as
       described in rule 3.
    """

    # See
    # http://msdn.microsoft.com/en-us/library/17w5ykft.aspx
    # or search http://msdn.microsoft.com for
    # "Parsing C++ Command-Line Arguments"
    result = []
    needquote = False
    for arg in seq:
        bs_buf = []

        # Add a space to separate this argument from the others
        if result:
            result.append(' ')

        needquote = (" " in arg) or ("\t" in arg) or not arg
        if needquote:
            result.append('"')

        for c in arg:
            if c == '\\':
                # Don't know if we need to double yet.
                bs_buf.append(c)
            elif c == '"':
                # Double backslashes.
                result.append('\\' * len(bs_buf)*2)
                bs_buf = []
                result.append('\\"')
            else:
                # Normal char
                if bs_buf:
                    result.extend(bs_buf)
                    bs_buf = []
                result.append(c)

        # Add remaining backslashes, if any.
        if bs_buf:
            result.extend(bs_buf)

        if needquote:
            result.extend(bs_buf)
            result.append('"')

    return ''.join(result)


# Various tools for executing commands and looking at their output and status.
#

def getstatusoutput(cmd):
    """    Return (status, output) of executing cmd in a shell.

    Execute the string 'cmd' in a shell with 'check_output' and
    return a 2-tuple (status, output). Universal newlines mode is used,
    meaning that the result with be decoded to a string.

    A trailing newline is stripped from the output.
    The exit status for the command can be interpreted
    according to the rules for the function 'wait'. Example:

    >>> import subprocess
    >>> subprocess.getstatusoutput('ls /bin/ls')
    (0, '/bin/ls')
    >>> subprocess.getstatusoutput('cat /bin/junk')
    (256, 'cat: /bin/junk: No such file or directory')
    >>> subprocess.getstatusoutput('/bin/junk')
    (256, 'sh: /bin/junk: not found')
    """
    try:
        data = check_output(cmd, shell=True, universal_newlines=True, stderr=STDOUT)
        status = 0
    except CalledProcessError as ex:
        data = ex.output
        status = ex.returncode
    if data[-1:] == '\n':
        data = data[:-1]
    return status, data

def getoutput(cmd):
    """Return output (stdout or stderr) of executing cmd in a shell.

    Like getstatusoutput(), except the exit status is ignored and the return
    value is a string containing the command's output.  Example:

    >>> import subprocess
    >>> subprocess.getoutput('ls /bin/ls')
    '/bin/ls'
    """
    return getstatusoutput(cmd)[1]


_PLATFORM_DEFAULT_CLOSE_FDS = object()


class Popen(object):

    _child_created = False  # Set here since __del__ checks it

    def __init__(self, args, bufsize=-1, executable=None,
                 stdin=None, stdout=None, stderr=None,
                 preexec_fn=None, close_fds=_PLATFORM_DEFAULT_CLOSE_FDS,
                 shell=False, cwd=None, env=None, universal_newlines=False,
                 startupinfo=None, creationflags=0,
                 restore_signals=True, start_new_session=False,
                 pass_fds=()):
        """Create new Popen instance."""
        _cleanup()
        # Held while anything is calling waitpid before returncode has been
        # updated to prevent clobbering returncode if wait() or poll() are
        # called from multiple threads at once.  After acquiring the lock,
        # code must re-check self.returncode to see if another thread just
        # finished a waitpid() call.
        self._waitpid_lock = threading.Lock()

        self._input = None
        self._communication_started = False
        if bufsize is None:
            bufsize = -1  # Restore default
        if not isinstance(bufsize, int):
            raise TypeError("bufsize must be an integer")

        if _mswindows:
            if preexec_fn is not None:
                raise ValueError("preexec_fn is not supported on Windows "
                                 "platforms")
            any_stdio_set = (stdin is not None or stdout is not None or
                             stderr is not None)
            if close_fds is _PLATFORM_DEFAULT_CLOSE_FDS:
                if any_stdio_set:
                    close_fds = False
                else:
                    close_fds = True
            elif close_fds and any_stdio_set:
                raise ValueError(
                        "close_fds is not supported on Windows platforms"
                        " if you redirect stdin/stdout/stderr")
        else:
            # POSIX
            if close_fds is _PLATFORM_DEFAULT_CLOSE_FDS:
                close_fds = True
            if pass_fds and not close_fds:
                warnings.warn("pass_fds overriding close_fds.", RuntimeWarning)
                close_fds = True
            if startupinfo is not None:
                raise ValueError("startupinfo is only supported on Windows "
                                 "platforms")
            if creationflags != 0:
                raise ValueError("creationflags is only supported on Windows "
                                 "platforms")

        self.args = args
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.pid = None
        self.returncode = None
        self.universal_newlines = universal_newlines

        # Input and output objects. The general principle is like
        # this:
        #
        # Parent                   Child
        # ------                   -----
        # p2cwrite   ---stdin--->  p2cread
        # c2pread    <--stdout---  c2pwrite
        # errread    <--stderr---  errwrite
        #
        # On POSIX, the child objects are file descriptors.  On
        # Windows, these are Windows file handles.  The parent objects
        # are file descriptors on both platforms.  The parent objects
        # are -1 when not using PIPEs. The child objects are -1
        # when not redirecting.

        (p2cread, p2cwrite,
         c2pread, c2pwrite,
         errread, errwrite) = self._get_handles(stdin, stdout, stderr)

        # We wrap OS handles *before* launching the child, otherwise a
        # quickly terminating child could make our fds unwrappable
        # (see #8458).

        if _mswindows:
            if p2cwrite != -1:
                p2cwrite = msvcrt.open_osfhandle(p2cwrite.Detach(), 0)
            if c2pread != -1:
                c2pread = msvcrt.open_osfhandle(c2pread.Detach(), 0)
            if errread != -1:
                errread = msvcrt.open_osfhandle(errread.Detach(), 0)

        if p2cwrite != -1:
            self.stdin = io.open(p2cwrite, 'wb', bufsize)
            if universal_newlines:
                self.stdin = io.TextIOWrapper(self.stdin, write_through=True,
                                              line_buffering=(bufsize == 1))
        if c2pread != -1:
            self.stdout = io.open(c2pread, 'rb', bufsize)
            if universal_newlines:
                self.stdout = io.TextIOWrapper(self.stdout)
        if errread != -1:
            self.stderr = io.open(errread, 'rb', bufsize)
            if universal_newlines:
                self.stderr = io.TextIOWrapper(self.stderr)

        self._closed_child_pipe_fds = False
        try:
            self._execute_child(args, executable, preexec_fn, close_fds,
                                pass_fds, cwd, env,
                                startupinfo, creationflags, shell,
                                p2cread, p2cwrite,
                                c2pread, c2pwrite,
                                errread, errwrite,
                                restore_signals, start_new_session)
        except:
            # Cleanup if the child failed starting.
            for f in filter(None, (self.stdin, self.stdout, self.stderr)):
                try:
                    f.close()
                except OSError:
                    pass  # Ignore EBADF or other errors.

            if not self._closed_child_pipe_fds:
                to_close = []
                if stdin == PIPE:
                    to_close.append(p2cread)
                if stdout == PIPE:
                    to_close.append(c2pwrite)
                if stderr == PIPE:
                    to_close.append(errwrite)
                if hasattr(self, '_devnull'):
                    to_close.append(self._devnull)
                for fd in to_close:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

            raise


    def _translate_newlines(self, data, encoding):
        data = data.decode(encoding)
        return data.replace("\r\n", "\n").replace("\r", "\n")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.stdout:
            self.stdout.close()
        if self.stderr:
            self.stderr.close()
        if self.stdin:
            self.stdin.close()
        # Wait for the process to terminate, to avoid zombies.
        self.wait()

    def __del__(self, _maxsize=sys.maxsize):
        if not self._child_created:
            # We didn't get to successfully create a child process.
            return
        # In case the child hasn't been waited on, check if it's done.
        self._internal_poll(_deadstate=_maxsize)
        if self.returncode is None and _active is not None:
            # Child is still running, keep us alive until we can wait on it.
            _active.append(self)

    def _get_devnull(self):
        if not hasattr(self, '_devnull'):
            self._devnull = os.open(os.devnull, os.O_RDWR)
        return self._devnull

    def communicate(self, input=None, timeout=None):
        """Interact with process: Send data to stdin.  Read data from
        stdout and stderr, until end-of-file is reached.  Wait for
        process to terminate.

        The optional "input" argument should be data to be sent to the
        child process (if self.universal_newlines is True, this should
        be a string; if it is False, "input" should be bytes), or
        None, if no data should be sent to the child.

        communicate() returns a tuple (stdout, stderr).  These will be
        bytes or, if self.universal_newlines was True, a string.
        """

        if self._communication_started and input:
            raise ValueError("Cannot send input after starting communication")

        # Optimization: If we are not worried about timeouts, we haven't
        # started communicating, and we have one or zero pipes, using select()
        # or threads is unnecessary.
        if (timeout is None and not self._communication_started and
            [self.stdin, self.stdout, self.stderr].count(None) >= 2):
            stdout = None
            stderr = None
            if self.stdin:
                if input:
                    try:
                        self.stdin.write(input)
                    except OSError as e:
                        if e.errno != errno.EPIPE and e.errno != errno.EINVAL:
                            raise
                self.stdin.close()
            elif self.stdout:
                stdout = _eintr_retry_call(self.stdout.read)
                self.stdout.close()
            elif self.stderr:
                stderr = _eintr_retry_call(self.stderr.read)
                self.stderr.close()
            self.wait()
        else:
            if timeout is not None:
                endtime = _time() + timeout
            else:
                endtime = None

            try:
                stdout, stderr = self._communicate(input, endtime, timeout)
            finally:
                self._communication_started = True

            sts = self.wait(timeout=self._remaining_time(endtime))

            stdout = b''.join(stdout or [])
            stderr = b''.join(stderr or [])
            if self.universal_newlines:
                if self.stdout is not None:
                    stdout = self._translate_newlines(stdout, self.stdout.encoding)
                if self.stderr is not None:
                    stderr = self._translate_newlines(stderr, self.stderr.encoding)
            stdout = None if self.stdout is None else stdout
            stderr = None if self.stderr is None else stderr

        return (stdout, stderr)


    def poll(self):
        return self._internal_poll()


    def _remaining_time(self, endtime):
        """Convenience for _communicate when computing timeouts."""
        if endtime is None:
            return None
        else:
            return endtime - _time()


    def _check_timeout(self, endtime, orig_timeout):
        """Convenience for checking if a timeout has expired."""
        if endtime is None:
            return
        if _time() > endtime:
            raise TimeoutExpired(self.args, orig_timeout)

    def read_nonblocking(self, bufsize=4096):
        """Reads any avialable data from the child stdout.
        """
        return self._read_nonblocking(self.stdout, max(bufsize, 1))

    def read_stderr_nonblocking(self, bufsize=4096):
        """Reads any available data from the child stderr.
        """
        return self._read_nonblocking(self.stderr, max(bufsize, 1))

    if _mswindows:
        #
        # Windows methods
        #
        def _get_handles(self, stdin, stdout, stderr):
            """Construct and return tuple with IO objects:
            p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite
            """
            if stdin is None and stdout is None and stderr is None:
                return (-1, -1, -1, -1, -1, -1)

            p2cread, p2cwrite = -1, -1
            c2pread, c2pwrite = -1, -1
            errread, errwrite = -1, -1

            if stdin is None:
                p2cread = _winapi.GetStdHandle(_winapi.STD_INPUT_HANDLE)
                if p2cread is None:
                    p2cread, _ = _winapi.CreatePipe(None, 0)
                    p2cread = Handle(p2cread)
                    _winapi.CloseHandle(_)
            elif stdin == PIPE:
                p2cread, p2cwrite = _pipe(overlapped=(False, True), duplex=True)
                p2cread, p2cwrite = Handle(p2cread), Handle(p2cwrite)
            elif stdin == DEVNULL:
                p2cread = msvcrt.get_osfhandle(self._get_devnull())
            elif isinstance(stdin, int):
                p2cread = msvcrt.get_osfhandle(stdin)
            else:
                # Assuming file-like object
                p2cread = msvcrt.get_osfhandle(stdin.fileno())
            p2cread = self._make_inheritable(p2cread)

            if stdout is None:
                c2pwrite = _winapi.GetStdHandle(_winapi.STD_OUTPUT_HANDLE)
                if c2pwrite is None:
                    _, c2pwrite = _winapi.CreatePipe(None, 0)
                    c2pwrite = Handle(c2pwrite)
                    _winapi.CloseHandle(_)
            elif stdout == PIPE:
                c2pread, c2pwrite = _pipe(overlapped=(True, False))
                c2pread, c2pwrite = Handle(c2pread), Handle(c2pwrite)
            elif stdout == DEVNULL:
                c2pwrite = msvcrt.get_osfhandle(self._get_devnull())
            elif isinstance(stdout, int):
                c2pwrite = msvcrt.get_osfhandle(stdout)
            else:
                # Assuming file-like object
                c2pwrite = msvcrt.get_osfhandle(stdout.fileno())
            c2pwrite = self._make_inheritable(c2pwrite)

            if stderr is None:
                errwrite = _winapi.GetStdHandle(_winapi.STD_ERROR_HANDLE)
                if errwrite is None:
                    _, errwrite = _winapi.CreatePipe(None, 0)
                    errwrite = Handle(errwrite)
                    _winapi.CloseHandle(_)
            elif stderr == PIPE:
                errread, errwrite = _pipe(overlapped=(True, False))
                errread, errwrite = Handle(errread), Handle(errwrite)
            elif stderr == STDOUT:
                errwrite = c2pwrite
            elif stderr == DEVNULL:
                errwrite = msvcrt.get_osfhandle(self._get_devnull())
            elif isinstance(stderr, int):
                errwrite = msvcrt.get_osfhandle(stderr)
            else:
                # Assuming file-like object
                errwrite = msvcrt.get_osfhandle(stderr.fileno())
            errwrite = self._make_inheritable(errwrite)

            return (p2cread, p2cwrite,
                    c2pread, c2pwrite,
                    errread, errwrite)


        def _make_inheritable(self, handle):
            """Return a duplicate of handle, which is inheritable"""
            h = _winapi.DuplicateHandle(
                _winapi.GetCurrentProcess(), handle,
                _winapi.GetCurrentProcess(), 0, 1,
                _winapi.DUPLICATE_SAME_ACCESS)
            return Handle(h)


        def _execute_child(self, args, executable, preexec_fn, close_fds,
                           pass_fds, cwd, env,
                           startupinfo, creationflags, shell,
                           p2cread, p2cwrite,
                           c2pread, c2pwrite,
                           errread, errwrite,
                           unused_restore_signals, unused_start_new_session):
            """Execute program (MS Windows version)"""

            assert not pass_fds, "pass_fds not supported on Windows."

            if not isinstance(args, str):
                args = list2cmdline(args)

            # Process startup details
            if startupinfo is None:
                startupinfo = STARTUPINFO()
            if -1 not in (p2cread, c2pwrite, errwrite):
                startupinfo.dwFlags |= _winapi.STARTF_USESTDHANDLES
                startupinfo.hStdInput = p2cread
                startupinfo.hStdOutput = c2pwrite
                startupinfo.hStdError = errwrite

            if shell:
                startupinfo.dwFlags |= _winapi.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = _winapi.SW_HIDE
                comspec = os.environ.get("COMSPEC", "cmd.exe")
                args = '{} /c "{}"'.format (comspec, args)

            # Start the process
            try:
                hp, ht, pid, tid = _winapi.CreateProcess(executable, args,
                                         # no special security
                                         None, None,
                                         int(not close_fds),
                                         creationflags,
                                         env,
                                         cwd,
                                         startupinfo)
            finally:
                # Child is launched. Close the parent's copy of those pipe
                # handles that only the child should have open.  You need
                # to make sure that no handles to the write end of the
                # output pipe are maintained in this process or else the
                # pipe will not close when the child process exits and the
                # ReadFile will hang.
                if p2cread != -1:
                    p2cread.Close()
                if c2pwrite != -1:
                    c2pwrite.Close()
                if errwrite != -1:
                    errwrite.Close()
                if hasattr(self, '_devnull'):
                    os.close(self._devnull)

            # Retain the process handle, but close the thread handle
            self._child_created = True
            self._handle = Handle(hp)
            self.pid = pid
            _winapi.CloseHandle(ht)

        def _internal_poll(self, _deadstate=None,
                _WaitForSingleObject=_winapi.WaitForSingleObject,
                _WAIT_OBJECT_0=_winapi.WAIT_OBJECT_0,
                _GetExitCodeProcess=_winapi.GetExitCodeProcess):
            """Check if child process has terminated.  Returns returncode
            attribute.

            This method is called by __del__, so it can only refer to objects
            in its local scope.

            """
            if self.returncode is None:
                if _WaitForSingleObject(self._handle, 0) == _WAIT_OBJECT_0:
                    self.returncode = _GetExitCodeProcess(self._handle)
            return self.returncode


        def wait(self, timeout=None, endtime=None):
            """Wait for child process to terminate.  Returns returncode
            attribute."""
            if endtime is not None:
                timeout = self._remaining_time(endtime)
            if timeout is None:
                timeout_millis = _winapi.INFINITE
            else:
                timeout_millis = int(timeout * 1000)
            if self.returncode is None:
                result = _winapi.WaitForSingleObject(self._handle,
                                                    timeout_millis)
                if result == _winapi.WAIT_TIMEOUT:
                    raise TimeoutExpired(self.args, timeout)
                self.returncode = _winapi.GetExitCodeProcess(self._handle)
            return self.returncode


        def _communicate(self, input, endtime, orig_timeout):
            # Prepare the output buffers for convenient access and the ability
            # to call .communicate() again.
            output = {}
            if self.stdout is not None:
                if not hasattr(self, "_stdout_buff"):
                    self._stdout_buff = []
                output['stdout'] = self._stdout_buff
            if self.stderr is not None:
                if not hasattr(self, "_stderr_buff"):
                    self._stderr_buff = []
                output['stderr'] = self._stderr_buff

            # Prepare our handles for reading
            h_or_none = lambda x: msvcrt.get_osfhandle(x.fileno()) if x else None
            handles = {'stdout': h_or_none(self.stdout),
                       'stderr': h_or_none(self.stderr)}

            # Also keep our pending_ios between calls if we need to re-call
            # communicate() after a timeout.
            pending_ios = getattr(self, '_pending_ios', [])
            self._pending_ios = pending_ios

            if self.stdin is not None and not self._communication_started:
                # Best part about overlapped IO? This right here. You can send
                # an arbitrarily large chunk of data to your child process, and
                # Windows will keep sending it in the background for you. You
                # just need to wait for it to complete, either due to a full
                # send, or the child dying.
                if input is None:
                    if not self._input:
                        self.stdin.close()
                    else:
                        # Wait until any earlier overlapped write completes
                        # before closing stdin.
                        pending_ios.append(
                            _OverlappedIO('stdin', self._input, self._input.event))
                else:
                    if self.universal_newlines:
                        input = input.encode(self.stdin.encoding)
                    ov = _overlapped.Overlapped()
                    try:
                        ov.WriteFile(msvcrt.get_osfhandle(self.stdin.fileno()), input)
                    except OSError:
                        # Ignore pipe errors and let anything else bubble up
                        # the stack. This preserves the pre-existing behavior.
                        pass
                    else:
                        # If we had any previously pending overlapped write,
                        # this write will still work just fine, so we can use
                        # this overlapped IO completion to signal closing the
                        # stdin pipe.
                        pending_ios.append(_OverlappedIO('stdin', ov, ov.event))

            def read(name):
                if handles[name]:
                    ov = _overlapped.Overlapped()
                    ov.ReadFile(handles[name], _READ_BLOCK_SIZE)
                    pending_ios.append(_OverlappedIO(name, ov, ov.event))

            # Prepare the stdout/stderr reads, as applicable
            if not self._communication_started:
                read('stdout')
                read('stderr')

            # Time for an event loop!
            while pending_ios:
                timeout = self._remaining_time(endtime)
                if timeout is not None and timeout < 0:
                    raise TimeoutExpired(self.args, orig_timeout)

                # Prepare the real timeout and wait for the pending IOs
                timeout = _WAIT if timeout is None else int(timeout * 1000)
                _winapi.WaitForMultipleObjects(
                    [io.event for io in pending_ios], False, min(timeout, _WAIT))

                # split the ios into completed and still pending
                completed = [p for p in pending_ios if not p.io.pending]
                pending_ios[:] = [p for p in pending_ios if p not in completed]

                # Process any completed io events
                for comp in completed:
                    # If we finished the stdin write, go ahead and close the
                    # stdin file handle to prevent subsequent writes.
                    if comp.name == 'stdin':
                        self.stdin.close()
                        continue

                    # As long as we've received a result from our read, there
                    # might be more data available on the other side. Keep
                    # trying to read from that handle.
                    result = comp.io.getresult()
                    if result:
                        output[comp.name].append(result)
                        read(comp.name)

            # Close stdout and stderr
            if self.stdout:
                self.stdout.close()
            if self.stderr:
                self.stderr.close()

            # Return the buffers (if any) to the communicate() method.
            stdout = self._stdout_buff if self.stdout else None
            stderr = self._stderr_buff if self.stderr else None

            return (stdout, stderr)

        def send_signal(self, sig):
            """Send a signal to the process
            """
            if sig == signal.SIGTERM:
                self.terminate()
            elif sig == signal.CTRL_C_EVENT:
                os.kill(self.pid, signal.CTRL_C_EVENT)
            elif sig == signal.CTRL_BREAK_EVENT:
                os.kill(self.pid, signal.CTRL_BREAK_EVENT)
            else:
                raise ValueError("Unsupported signal: {}".format(sig))

        def terminate(self):
            """Terminates the process
            """
            try:
                _winapi.TerminateProcess(self._handle, 1)
            except PermissionError:
                # ERROR_ACCESS_DENIED (winerror 5) is received when the
                # process already died.
                rc = _winapi.GetExitCodeProcess(self._handle)
                if rc == _winapi.STILL_ACTIVE:
                    raise
                self.returncode = rc

        kill = terminate

        def write_nonblocking(self, input, timeout=0):
            """Writes as much input to the child stdin as possible, returns the
            number of bytes written.
            """
            if self._input:
                if self._input.error not in (0, _winapi.ERROR_IO_PENDING):
                    raise Exception("got overlapped result error: %s" % self._input.error)

                # Don't accept any more IOs until the last one is done
                if self._input.pending:
                    return 0

                # Get the result and discard it.
                self._input.getresult(True)
                self._input = None

            if not input:
                return 0

            handle = msvcrt.get_osfhandle(self.stdin.fileno())
            self._input = ov = _overlapped.Overlapped()
            ov.WriteFile(handle, input)

            if ov.error not in (0, _winapi.ERROR_IO_PENDING):
                self._input = None
                raise Exception("got overlapped result error: %s"%ov.error)

            if timeout > 0:
                _winapi.WaitForSingleObject(handle, min(int(timeout * 1000), _WAIT))

            # return that we sent all the input, even if it is still pending
            return len(input)

        def _read_nonblocking(self, pipe, bufsize):
            # Handle circular dependency.
            handle = msvcrt.get_osfhandle(pipe.fileno())
            avail = _winapi.PeekNamedPipe(handle, 0)[0]
            if avail > 0:
                # The use of overlapped IOs here is necessary as per
                # documentation on ReadFile.
                ov = _overlapped.Overlapped()
                ov.ReadFile(handle, min(bufsize, avail))
                return ov.getresult(True)

    else:
        #
        # POSIX methods
        #
        def _get_handles(self, stdin, stdout, stderr):
            """Construct and return tuple with IO objects:
            p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite
            """
            p2cread, p2cwrite = -1, -1
            c2pread, c2pwrite = -1, -1
            errread, errwrite = -1, -1

            if stdin is None:
                pass
            elif stdin == PIPE:
                p2cread, p2cwrite = os.pipe()
            elif stdin == DEVNULL:
                p2cread = self._get_devnull()
            elif isinstance(stdin, int):
                p2cread = stdin
            else:
                # Assuming file-like object
                p2cread = stdin.fileno()

            if stdout is None:
                pass
            elif stdout == PIPE:
                c2pread, c2pwrite = os.pipe()
            elif stdout == DEVNULL:
                c2pwrite = self._get_devnull()
            elif isinstance(stdout, int):
                c2pwrite = stdout
            else:
                # Assuming file-like object
                c2pwrite = stdout.fileno()

            if stderr is None:
                pass
            elif stderr == PIPE:
                errread, errwrite = os.pipe()
            elif stderr == STDOUT:
                errwrite = c2pwrite
            elif stderr == DEVNULL:
                errwrite = self._get_devnull()
            elif isinstance(stderr, int):
                errwrite = stderr
            else:
                # Assuming file-like object
                errwrite = stderr.fileno()

            return (p2cread, p2cwrite,
                    c2pread, c2pwrite,
                    errread, errwrite)


        def _close_fds(self, fds_to_keep):
            start_fd = 3
            for fd in sorted(fds_to_keep):
                if fd >= start_fd:
                    os.closerange(start_fd, fd)
                    start_fd = fd + 1
            if start_fd <= MAXFD:
                os.closerange(start_fd, MAXFD)


        def _execute_child(self, args, executable, preexec_fn, close_fds,
                           pass_fds, cwd, env,
                           startupinfo, creationflags, shell,
                           p2cread, p2cwrite,
                           c2pread, c2pwrite,
                           errread, errwrite,
                           restore_signals, start_new_session):
            """Execute program (POSIX version)"""

            if isinstance(args, (str, bytes)):
                args = [args]
            else:
                args = list(args)

            if shell:
                args = ["/bin/sh", "-c"] + args
                if executable:
                    args[0] = executable

            if executable is None:
                executable = args[0]
            orig_executable = executable

            # For transferring possible exec failure from child to parent.
            # Data format: "exception name:hex errno:description"
            # Pickle is not used; it is complex and involves memory allocation.
            errpipe_read, errpipe_write = os.pipe()
            # errpipe_write must not be in the standard io 0, 1, or 2 fd range.
            low_fds_to_close = []
            while errpipe_write < 3:
                low_fds_to_close.append(errpipe_write)
                errpipe_write = os.dup(errpipe_write)
            for low_fd in low_fds_to_close:
                os.close(low_fd)
            try:
                try:
                    if _posixsubprocess:
                        # We must avoid complex work that could involve
                        # malloc or free in the child process to avoid
                        # potential deadlocks, thus we do all this here.
                        # and pass it to fork_exec()

                        if env:
                            env_list = [os.fsencode(k) + b'=' + os.fsencode(v)
                                        for k, v in env.items()]
                        else:
                            env_list = None  # Use execv instead of execve.
                        executable = os.fsencode(executable)
                        if os.path.dirname(executable):
                            executable_list = (executable,)
                        else:
                            # This matches the behavior of os._execvpe().
                            executable_list = tuple(
                                os.path.join(os.fsencode(dir), executable)
                                for dir in os.get_exec_path(env))
                        fds_to_keep = set(pass_fds)
                        fds_to_keep.add(errpipe_write)
                        self.pid = _posixsubprocess.fork_exec(
                                args, executable_list,
                                close_fds, sorted(fds_to_keep), cwd, env_list,
                                p2cread, p2cwrite, c2pread, c2pwrite,
                                errread, errwrite,
                                errpipe_read, errpipe_write,
                                restore_signals, start_new_session, preexec_fn)
                    else:
                        # Pure Python implementation: It is not thread safe.
                        # This implementation may deadlock in the child if your
                        # parent process has any other threads running.

                        gc_was_enabled = gc.isenabled()
                        # Disable gc to avoid bug where gc -> file_dealloc ->
                        # write to stderr -> hang.  See issue1336
                        gc.disable()
                        try:
                            self.pid = os.fork()
                        except:
                            if gc_was_enabled:
                                gc.enable()
                            raise
                        self._child_created = True
                        if self.pid == 0:
                            # Child
                            try:
                                # Close parent's pipe ends
                                if p2cwrite != -1:
                                    os.close(p2cwrite)
                                if c2pread != -1:
                                    os.close(c2pread)
                                if errread != -1:
                                    os.close(errread)
                                os.close(errpipe_read)

                                # Dup fds for child
                                def _dup2(a, b):
                                    # dup2() removes the CLOEXEC flag but
                                    # we must do it ourselves if dup2()
                                    # would be a no-op (issue #10806).
                                    if a == b:
                                        _set_cloexec(a, False)
                                    elif a != -1:
                                        os.dup2(a, b)
                                _dup2(p2cread, 0)
                                _dup2(c2pwrite, 1)
                                _dup2(errwrite, 2)

                                # Close pipe fds.  Make sure we don't close the
                                # same fd more than once, or standard fds.
                                closed = set()
                                for fd in [p2cread, c2pwrite, errwrite]:
                                    if fd > 2 and fd not in closed:
                                        os.close(fd)
                                        closed.add(fd)

                                # Close all other fds, if asked for
                                if close_fds:
                                    fds_to_keep = set(pass_fds)
                                    fds_to_keep.add(errpipe_write)
                                    self._close_fds(fds_to_keep)


                                if cwd is not None:
                                    os.chdir(cwd)

                                # This is a copy of Python/pythonrun.c
                                # _Py_RestoreSignals().  If that were exposed
                                # as a sys._py_restoresignals func it would be
                                # better.. but this pure python implementation
                                # isn't likely to be used much anymore.
                                if restore_signals:
                                    signals = ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ')
                                    for sig in signals:
                                        if hasattr(signal, sig):
                                            signal.signal(getattr(signal, sig),
                                                          signal.SIG_DFL)

                                if start_new_session and hasattr(os, 'setsid'):
                                    os.setsid()

                                if preexec_fn:
                                    preexec_fn()

                                if env is None:
                                    os.execvp(executable, args)
                                else:
                                    os.execvpe(executable, args, env)

                            except:
                                try:
                                    exc_type, exc_value = sys.exc_info()[:2]
                                    if isinstance(exc_value, OSError):
                                        errno_num = exc_value.errno
                                    else:
                                        errno_num = 0
                                    message = '%s:%x:%s' % (exc_type.__name__,
                                                            errno_num, exc_value)
                                    message = message.encode(errors="surrogatepass")
                                    os.write(errpipe_write, message)
                                except Exception:
                                    # We MUST not allow anything odd happening
                                    # above to prevent us from exiting below.
                                    pass

                            # This exitcode won't be reported to applications
                            # so it really doesn't matter what we return.
                            os._exit(255)

                        # Parent
                        if gc_was_enabled:
                            gc.enable()
                finally:
                    # be sure the FD is closed no matter what
                    os.close(errpipe_write)

                # self._devnull is not always defined.
                devnull_fd = getattr(self, '_devnull', None)
                if p2cread != -1 and p2cwrite != -1 and p2cread != devnull_fd:
                    os.close(p2cread)
                if c2pwrite != -1 and c2pread != -1 and c2pwrite != devnull_fd:
                    os.close(c2pwrite)
                if errwrite != -1 and errread != -1 and errwrite != devnull_fd:
                    os.close(errwrite)
                if devnull_fd is not None:
                    os.close(devnull_fd)
                # Prevent a double close of these fds from __init__ on error.
                self._closed_child_pipe_fds = True

                # Wait for exec to fail or succeed; possibly raising an
                # exception (limited in size)
                errpipe_data = bytearray()
                #while True:
                #    part = _eintr_retry_call(os.read, errpipe_read, 50000)
                #    errpipe_data += part
                #    if not part or len(errpipe_data) > 50000:
                #        break
            finally:
                # be sure the FD is closed no matter what
                os.close(errpipe_read)

            if errpipe_data:
                try:
                    _eintr_retry_call(os.waitpid, self.pid, 0)
                except OSError as e:
                    if e.errno != errno.ECHILD:
                        raise
                try:
                    exception_name, hex_errno, err_msg = (
                            errpipe_data.split(b':', 2))
                except ValueError:
                    exception_name = b'SubprocessError'
                    hex_errno = b'0'
                    err_msg = (b'Bad exception data from child: ' +
                               repr(errpipe_data))
                child_exception_type = getattr(
                        builtins, exception_name.decode('ascii'),
                        SubprocessError)
                err_msg = err_msg.decode(errors="surrogatepass")
                if issubclass(child_exception_type, OSError) and hex_errno:
                    errno_num = int(hex_errno, 16)
                    child_exec_never_called = (err_msg == "noexec")
                    if child_exec_never_called:
                        err_msg = ""
                    if errno_num != 0:
                        err_msg = os.strerror(errno_num)
                        if errno_num == errno.ENOENT:
                            if child_exec_never_called:
                                # The error must be from chdir(cwd).
                                err_msg += ': ' + repr(cwd)
                            else:
                                err_msg += ': ' + repr(orig_executable)
                    raise child_exception_type(errno_num, err_msg)
                raise child_exception_type(err_msg)


        def _handle_exitstatus(self, sts, _WIFSIGNALED=os.WIFSIGNALED,
                _WTERMSIG=os.WTERMSIG, _WIFEXITED=os.WIFEXITED,
                _WEXITSTATUS=os.WEXITSTATUS):
            """All callers to this function MUST hold self._waitpid_lock."""
            # This method is called (indirectly) by __del__, so it cannot
            # refer to anything outside of its local scope.
            if _WIFSIGNALED(sts):
                self.returncode = -_WTERMSIG(sts)
            elif _WIFEXITED(sts):
                self.returncode = _WEXITSTATUS(sts)
            else:
                # Should never happen
                raise SubprocessError("Unknown child exit status!")


        def _internal_poll(self, _deadstate=None, _waitpid=os.waitpid,
                _WNOHANG=os.WNOHANG, _ECHILD=errno.ECHILD):
            """Check if child process has terminated.  Returns returncode
            attribute.

            This method is called by __del__, so it cannot reference anything
            outside of the local scope (nor can any methods it calls).

            """
            if self.returncode is None:
                if not self._waitpid_lock.acquire(False):
                    # Something else is busy calling waitpid.  Don't allow two
                    # at once.  We know nothing yet.
                    return None
                try:
                    if self.returncode is not None:
                        return self.returncode  # Another thread waited.
                    pid, sts = _waitpid(self.pid, _WNOHANG)
                    if pid == self.pid:
                        self._handle_exitstatus(sts)
                except OSError as e:
                    if _deadstate is not None:
                        self.returncode = _deadstate
                    elif e.errno == _ECHILD:
                        # This happens if SIGCLD is set to be ignored or
                        # waiting for child processes has otherwise been
                        # disabled for our process.  This child is dead, we
                        # can't get the status.
                        # http://bugs.python.org/issue15756
                        self.returncode = 0
                finally:
                    self._waitpid_lock.release()
            return self.returncode


        def _try_wait(self, wait_flags):
            """All callers to this function MUST hold self._waitpid_lock."""
            try:
                (pid, sts) = _eintr_retry_call(os.waitpid, self.pid, wait_flags)
            except OSError as e:
                if e.errno != errno.ECHILD:
                    raise
                # This happens if SIGCLD is set to be ignored or waiting
                # for child processes has otherwise been disabled for our
                # process.  This child is dead, we can't get the status.
                pid = self.pid
                sts = 0
            return (pid, sts)


        def wait(self, timeout=None, endtime=None):
            """Wait for child process to terminate.  Returns returncode
            attribute."""
            if self.returncode is not None:
                return self.returncode

            # endtime is preferred to timeout.  timeout is only used for
            # printing.
            if endtime is not None or timeout is not None:
                if endtime is None:
                    endtime = _time() + timeout
                elif timeout is None:
                    timeout = self._remaining_time(endtime)

            if endtime is not None:
                # Enter a busy loop if we have a timeout.  This busy loop was
                # cribbed from Lib/threading.py in Thread.wait() at r71065.
                delay = 0.0005 # 500 us -> initial delay of 1 ms
                while True:
                    if self._waitpid_lock.acquire(False):
                        try:
                            if self.returncode is not None:
                                break  # Another thread waited.
                            (pid, sts) = self._try_wait(os.WNOHANG)
                            assert pid == self.pid or pid == 0
                            if pid == self.pid:
                                self._handle_exitstatus(sts)
                                break
                        finally:
                            self._waitpid_lock.release()
                    remaining = self._remaining_time(endtime)
                    if remaining <= 0:
                        raise TimeoutExpired(self.args, timeout)
                    delay = min(delay * 2, remaining, .05)
                    time.sleep(delay)
            else:
                while self.returncode is None:
                    with self._waitpid_lock:
                        if self.returncode is not None:
                            break  # Another thread waited.
                        (pid, sts) = self._try_wait(0)
                        # Check the pid and loop as waitpid has been known to
                        # return 0 even without WNOHANG in odd situations.
                        # http://bugs.python.org/issue14396.
                        if pid == self.pid:
                            self._handle_exitstatus(sts)
            return self.returncode


        def _communicate(self, input, endtime, orig_timeout):
            if self.stdin and not self._communication_started:
                # Flush stdio buffer.  This might block, if the user has
                # been writing to .stdin in an uncontrolled fashion.
                self.stdin.flush()
                if not input:
                    self.stdin.close()

            stdout = None
            stderr = None

            # Only create this mapping if we haven't already.
            if not self._communication_started:
                self._fileobj2output = {}
                if self.stdout:
                    self._fileobj2output[self.stdout] = []
                if self.stderr:
                    self._fileobj2output[self.stderr] = []

            if self.stdout:
                stdout = self._fileobj2output[self.stdout]
            if self.stderr:
                stderr = self._fileobj2output[self.stderr]

            self._save_input(input)

            if self._input:
                input_view = memoryview(self._input)

            with _PopenSelector() as selector:
                if self.stdin and input:
                    selector.register(self.stdin, EVENT_WRITE)
                if self.stdout:
                    selector.register(self.stdout, EVENT_READ)
                if self.stderr:
                    selector.register(self.stderr, EVENT_READ)

                while selector.get_map():
                    timeout = self._remaining_time(endtime)
                    if timeout is not None and timeout < 0:
                        raise TimeoutExpired(self.args, orig_timeout)

                    ready = selector.select(timeout)
                    self._check_timeout(endtime, orig_timeout)

                    # XXX Rewrite these to use non-blocking I/O on the file
                    # objects; they are no longer using C stdio!

                    for key, events in ready:
                        if key.fileobj is self.stdin:
                            chunk = input_view[self._input_offset :
                                               self._input_offset + _PIPE_BUF]
                            try:
                                self._input_offset += os.write(key.fd, chunk)
                            except OSError as e:
                                if e.errno == errno.EPIPE:
                                    selector.unregister(key.fileobj)
                                    key.fileobj.close()
                                else:
                                    raise
                            else:
                                if self._input_offset >= len(self._input):
                                    selector.unregister(key.fileobj)
                                    key.fileobj.close()
                        elif key.fileobj in (self.stdout, self.stderr):
                            data = os.read(key.fd, _READ_BLOCK_SIZE)
                            if not data:
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            self._fileobj2output[key.fileobj].append(data)

            self.wait(timeout=self._remaining_time(endtime))

            # Return the buffers (if any) to the communicate() method.
            return (stdout, stderr)


        def _save_input(self, input):
            # This method is called from the _communicate_with_*() methods
            # so that if we time out while communicating, we can continue
            # sending input if we retry.
            if self.stdin and self._input is None:
                self._input_offset = 0
                self._input = input
                if self.universal_newlines and input is not None:
                    self._input = self._input.encode(self.stdin.encoding)


        def send_signal(self, sig):
            """Send a signal to the process
            """
            os.kill(self.pid, sig)

        def terminate(self):
            """Terminate the process with SIGTERM
            """
            self.send_signal(signal.SIGTERM)

        def kill(self):
            """Kill the process with SIGKILL
            """
            self.send_signal(signal.SIGKILL)

        def write_nonblocking(self, input, timeout=0):
            """Writes as much input to the child stdin as possible, returns the
            number of bytes written.
            """
            with _PopenSelector() as selector:
                selector.register(self.stdin, EVENT_WRITE)

                if selector.select(max(timeout, 0)):
                    return os.write(self.stdin.fileno(), input)
                return 0

        def _read_nonblocking(self, pipe, bufsize):
            # Yes, fcntl non-blocking bit flipping is necessary for this to
            # work.
            flags = fcntl.fcntl(pipe, fcntl.F_GETFL)
            fcntl.fcntl(pipe, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            try:
                with _PopenSelector() as selector:
                    selector.register(pipe, EVENT_READ)
  
                    if selector.select(0):
                        ret = os.read(pipe.fileno(), bufsize)
                        if not ret:
                            # Zero byte read after being readable == closed
                            raise EOFError()
                        return ret

                    return b''
            finally:
                if not pipe.closed:
                    fcntl.fcntl(pipe, fcntl.F_SETFL, flags)
