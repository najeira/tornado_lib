"""A POP3 client class.

Based on the J. Myers POP3 draft, Jan. 96
"""

# Author: David Ascher <david_ascher@brown.edu>
#         [heavily stealing from nntplib.py]
# Updated: Piers Lauder <piers@cs.su.oz.au> [Jul '97]
# String method conversion and test jig improvements by ESR, February 2001.
# Added the POP3_SSL class. Methods loosely based on IMAP_SSL. Hector Urtubia <urtubia@mrbook.org> Aug 2003

# Example (see the test function at the end of this file)

# Imports

import re, socket
from tornado import gen
from tornado import iostream

__all__ = ["POP3","error_proto"]

# Exception raised when an error or invalid response is received:

class error_proto(Exception): pass

# Standard Port
POP3_PORT = 110

# POP SSL PORT
POP3_SSL_PORT = 995

# Line terminators (we always output CRLF, but accept any of CRLF, LFCR, LF)
CR = '\r'
LF = '\n'
CRLF = CR+LF


class POP3:

    """This class supports both the minimal and optional command sets.
    Arguments can be strings or integers (where appropriate)
    (e.g.: retr(1) and retr('1') both work equally well.

    Minimal Command Set:
            USER name               user(name)
            PASS string             pass_(string)
            STAT                    stat()
            LIST [msg]              list(msg = None)
            RETR msg                retr(msg)
            DELE msg                dele(msg)
            NOOP                    noop()
            RSET                    rset()
            QUIT                    quit()

    Optional Commands (some servers support these):
            RPOP name               rpop(name)
            APOP name digest        apop(name, digest)
            TOP msg n               top(msg, n)
            UIDL [msg]              uidl(msg = None)

    Raises one exception: 'error_proto'.

    Instantiate with:
            POP3(hostname, port=110)

    NB:     the POP protocol locks the mailbox from user
            authorization until QUIT, so be sure to get in, suck
            the messages, and quit, each time you access the
            mailbox.

            POP is a line-based protocol, which means large mail
            messages consume lots of python cycles reading them
            line-by-line.

            If it's available on your mail server, use IMAP4
            instead, it doesn't suffer from the two problems
            above.
    """


    def __init__(self, host, port=POP3_PORT,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self._debugging = 0
        self.stream, self.sockaddr = self.get_stream(timeout)


    def get_socket(self, timeout):
        sock = sockaddr = None
        for res in socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM):
            family, socktype, proto, canonname, sockaddr = res
            try:
                sock = socket.socket(family, socktype, proto)
                break
            except socket.error:
                sock = None
        if not sock:
            raise
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        return sock, sockaddr


    def get_stream(self, timeout):
        sock, sockaddr = self.get_socket(timeout)
        return iostream.IOStream(sock), sockaddr


    @gen.engine
    def connect(self, callback):
        yield gen.Task(self.stream.connect, self.sockaddr)
        self.welcome = yield gen.Task(self._getresp)
        callback(self.welcome)


    def _putline(self, line, callback):
        if self._debugging > 1: print '*put*', repr(line)
        self.stream.write('%s%s' % (line, CRLF), callback)


    # Internal: send one command to the server (through _putline())

    def _putcmd(self, line, callback):
        if self._debugging: print '*cmd*', repr(line)
        self._putline(line, callback)


    # Internal: return one line from the server, stripping CRLF.
    # This is where all the CPU time of this module is consumed.
    # Raise error_proto('-ERR EOF') if the connection is closed.

    @gen.engine
    def _getline(self, callback):
        line = yield gen.Task(self.stream.read_until, '\n')
        if self._debugging > 1: print '*get*', repr(line)
        if not line: raise error_proto('-ERR EOF')
        octets = len(line)
        # server can send any combination of CR & LF
        # however, 'readline()' returns lines ending in LF
        # so only possibilities are ...LF, ...CRLF, CR...LF
        if line[-2:] == CRLF:
            callback((line[:-2], octets))
        elif line[0] == CR:
            callback((line[1:-1], octets))
        else:
            callback((line[:-1], octets))


    # Internal: get a response from the server.
    # Raise 'error_proto' if the response doesn't start with '+'.

    @gen.engine
    def _getresp(self, callback):
        resp, o = yield gen.Task(self._getline)
        if self._debugging > 1: print '*resp*', repr(resp)
        c = resp[:1]
        if c != '+':
            raise error_proto(resp)
        callback(resp)


    # Internal: get a response plus following text from the server.

    @gen.engine
    def _getlongresp(self, callback):
        resp = yield gen.Task(self._getresp)
        list = []; octets = 0
        line, o = yield gen.Task(self._getline)
        while line != '.':
            if line[:2] == '..':
                o = o-1
                line = line[1:]
            octets = octets + o
            list.append(line)
            line, o = yield gen.Task(self._getline)
        callback((resp, list, octets))


    # Internal: send a command and get the response

    @gen.engine
    def _shortcmd(self, line, callback):
        yield gen.Task(self._putcmd, line)
        self._getresp(callback)


    # Internal: send a command and get the response plus following text

    @gen.engine
    def _longcmd(self, line, callback):
        yield gen.Task(self._putcmd, line)
        self._getlongresp(callback)


    # These can be useful:

    def getwelcome(self):
        return self.welcome


    def set_debuglevel(self, level):
        self._debugging = level


    # Here are all the POP commands:

    @gen.engine
    def user(self, user, callback):
        """Send user name, return response

        (should indicate password required).
        """
        self._shortcmd('USER %s' % user, callback)


    @gen.engine
    def pass_(self, pswd, callback):
        """Send password, return response

        (response includes message count, mailbox size).

        NB: mailbox is locked by server from here to 'quit()'
        """
        self._shortcmd('PASS %s' % pswd, callback)


    @gen.engine
    def stat(self, callback):
        """Get mailbox status.

        Result is tuple of 2 ints (message count, mailbox size)
        """
        retval = yield gen.Task(self._shortcmd, 'STAT')
        rets = retval.split()
        if self._debugging: print '*stat*', repr(rets)
        numMessages = int(rets[1])
        sizeMessages = int(rets[2])
        callback((numMessages, sizeMessages))


    @gen.engine
    def list(self, which=None, callback=None):
        """Request listing, return result.

        Result without a message number argument is in form
        ['response', ['mesg_num octets', ...], octets].

        Result when a message number argument is given is a
        single response: the "scan listing" for that message.
        """
        if which is not None:
            self._shortcmd('LIST %s' % which, callback)
        else:
            self._longcmd('LIST', callback)


    @gen.engine
    def retr(self, which, callback):
        """Retrieve whole message number 'which'.

        Result is in form ['response', ['line', ...], octets].
        """
        self._longcmd('RETR %s' % which, callback)


    @gen.engine
    def dele(self, which, callback):
        """Delete message number 'which'.

        Result is 'response'.
        """
        self._shortcmd('DELE %s' % which, callback)


    @gen.engine
    def noop(self, callback):
        """Does nothing.

        One supposes the response indicates the server is alive.
        """
        self._shortcmd('NOOP', callback)


    @gen.engine
    def rset(self, callback):
        """Unmark all messages marked for deletion."""
        self._shortcmd('RSET', callback)


    def close(self):
        if self.stream:
            self.stream.close()
        self.stream = None


    @gen.engine
    def quit(self, callback):
        """Signoff: commit changes on server, unlock mailbox, close connection."""
        try:
            resp = yield gen.Task(self._shortcmd, 'QUIT')
        except error_proto, val:
            resp = val
        self.close()
        callback(resp)

    #__del__ = quit


    # optional commands:

    @gen.engine
    def rpop(self, user, callback):
        """Not sure what this does."""
        self._shortcmd('RPOP %s' % user, callback)


    timestamp = re.compile(r'\+OK.*(<[^>]+>)')

    @gen.engine
    def apop(self, user, secret, callback):
        """Authorisation

        - only possible if server has supplied a timestamp in initial greeting.

        Args:
                user    - mailbox user;
                secret  - secret shared between client and server.

        NB: mailbox is locked by server from here to 'quit()'
        """
        m = self.timestamp.match(self.welcome)
        if not m:
            raise error_proto('-ERR APOP not supported by server')
        import hashlib
        digest = hashlib.md5(m.group(1)+secret).digest()
        digest = ''.join(map(lambda x:'%02x'%ord(x), digest))
        self._shortcmd('APOP %s %s' % (user, digest), callback)


    @gen.engine
    def top(self, which, howmuch, callback):
        """Retrieve message header of message number 'which'
        and first 'howmuch' lines of message body.

        Result is in form ['response', ['line', ...], octets].
        """
        self._longcmd('TOP %s %s' % (which, howmuch), callback)


    @gen.engine
    def uidl(self, which=None, callback=None):
        """Return message digest (unique id) list.

        If 'which', result contains unique id for that message
        in the form 'response mesgnum uid', otherwise result is
        the list ['response', ['mesgnum uid', ...], octets]
        """
        if which is not None:
            self._shortcmd('UIDL %s' % which, callback)
        else:
            self._longcmd('UIDL', callback)

try:
    import ssl
except ImportError:
    pass
else:

    class POP3_SSL(POP3):
        """POP3 client class over SSL connection

        Instantiate with: POP3_SSL(hostname, port=995, keyfile=None, certfile=None)

               hostname - the hostname of the pop3 over ssl server
               port - port number
               keyfile - PEM formatted file that countains your private key
               certfile - PEM formatted certificate chain file

            See the methods of the parent class POP3 for more documentation.
        """

        def __init__(self, host, port = POP3_SSL_PORT, keyfile = None, certfile = None):
            self.host = host
            self.port = port
            self.keyfile = keyfile
            self.certfile = certfile
            self._debugging = 0
            self.stream, self.sockaddr = self.get_stream(timeout)

        def get_stream(self, timeout):
            sock, sockaddr = self.get_socket(timeout)
            ssl_sock = ssl.wrap_socket(sock, self.keyfile, self.certfile)
            return iostream.SSLIOStream(ssl_sock), sockaddr

    __all__.append("POP3_SSL")

if __name__ == "__main__":
    import sys
    a = POP3(sys.argv[1])
    print a.getwelcome()
    a.user(sys.argv[2])
    a.pass_(sys.argv[3])
    a.list()
    (numMsgs, totalSize) = a.stat()
    for i in range(1, numMsgs + 1):
        (header, msg, octets) = a.retr(i)
        print "Message %d:" % i
        for line in msg:
            print '   ' + line
        print '-----------------------'
    a.quit()
