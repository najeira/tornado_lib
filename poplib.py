# -*- coding: utf-8 -*-

import re
import socket
import ssl
from tornado import gen
from tornado import iostream

__all__ = ["POP3", "Error"]

POP3_PORT = 110
POP3_SSL_PORT = 995
CR = '\r'
LF = '\n'
CRLF = CR+LF


class Error(Exception):
  pass


class POP3(object):
  
  def __init__(self, host, port=POP3_PORT, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
    self.host = host
    self.port = port
    self.timeout = timeout
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
  
  def _putcmd(self, line, callback):
    if self._debugging: print '*cmd*', repr(line)
    self._putline(line, callback)
  
  @gen.engine
  def _getline(self, callback):
    line = yield gen.Task(self.stream.read_until, '\n')
    if self._debugging > 1: print '*get*', repr(line)
    if not line: raise Error('-ERR EOF')
    octets = len(line)
    if line[-2:] == CRLF:
      callback((line[:-2], octets))
    elif line[0] == CR:
      callback((line[1:-1], octets))
    else:
      callback((line[:-1], octets))
  
  @gen.engine
  def _getresp(self, callback):
    resp, o = yield gen.Task(self._getline)
    if self._debugging > 1: print '*resp*', repr(resp)
    c = resp[:1]
    if c != '+':
      raise Error(resp)
    callback(resp)
  
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
  
  @gen.engine
  def _shortcmd(self, line, callback):
    yield gen.Task(self._putcmd, line)
    self._getresp(callback)
  
  @gen.engine
  def _longcmd(self, line, callback):
    yield gen.Task(self._putcmd, line)
    self._getlongresp(callback)
  
  def getwelcome(self):
    return self.welcome
  
  def set_debuglevel(self, level):
    self._debugging = level
  
  @gen.engine
  def user(self, user, callback):
    self._shortcmd('USER %s' % user, callback)
  
  @gen.engine
  def pass_(self, pswd, callback):
    self._shortcmd('PASS %s' % pswd, callback)
  
  @gen.engine
  def stat(self, callback):
    retval = yield gen.Task(self._shortcmd, 'STAT')
    rets = retval.split()
    if self._debugging: print '*stat*', repr(rets)
    numMessages = int(rets[1])
    sizeMessages = int(rets[2])
    callback((numMessages, sizeMessages))
  
  @gen.engine
  def list(self, which=None, callback=None):
    if which is not None:
      self._shortcmd('LIST %s' % which, callback)
    else:
      self._longcmd('LIST', callback)
  
  @gen.engine
  def retr(self, which, callback):
    self._longcmd('RETR %s' % which, callback)
  
  @gen.engine
  def dele(self, which, callback):
    self._shortcmd('DELE %s' % which, callback)
  
  @gen.engine
  def noop(self, callback):
    self._shortcmd('NOOP', callback)
  
  @gen.engine
  def rset(self, callback):
    self._shortcmd('RSET', callback)
  
  def close(self):
    if self.stream:
      self.stream.close()
    self.stream = None
  
  @gen.engine
  def quit(self, callback):
    try:
      resp = yield gen.Task(self._shortcmd, 'QUIT')
    except Error, val:
      resp = val
    self.close()
    callback(resp)
  
  @gen.engine
  def rpop(self, user, callback):
    self._shortcmd('RPOP %s' % user, callback)
  
  timestamp = re.compile(r'\+OK.*(<[^>]+>)')
  
  @gen.engine
  def apop(self, user, secret, callback):
    m = self.timestamp.match(self.welcome)
    if not m:
      raise Error('-ERR APOP not supported by server')
    import hashlib
    digest = hashlib.md5(m.group(1)+secret).digest()
    digest = ''.join(map(lambda x:'%02x'%ord(x), digest))
    self._shortcmd('APOP %s %s' % (user, digest), callback)
  
  @gen.engine
  def top(self, which, howmuch, callback):
    self._longcmd('TOP %s %s' % (which, howmuch), callback)
  
  @gen.engine
  def uidl(self, which=None, callback=None):
    if which is not None:
      self._shortcmd('UIDL %s' % which, callback)
    else:
      self._longcmd('UIDL', callback)

class POP3_SSL(POP3):
  
  def __init__(self, host, port=POP3_SSL_PORT, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
    keyfile=None, certfile=None):
    self.host = host
    self.port = port
    self.keyfile = keyfile
    self.certfile = certfile
    self._debugging = 0
    self.stream = self.get_stream(timeout)
  
  def get_stream(self, timeout):
    sock, sockaddr = self.get_socket(timeout)
    ssl_sock = ssl.wrap_socket(sock, self.keyfile, self.certfile)
    return iostream.SSLIOStream(ssl_sock), sockaddr

if __name__ == "__main__":
  import sys
  
  @gen.engine
  def main(callback):
    a = POP3(sys.argv[1])
    print(yield gen.Task(a.connect))
    try:
      print(yield gen.Task(a.user, sys.argv[2]))
      print(yield gen.Task(a.pass_, sys.argv[3]))
      numMsgs, totalSize = yield gen.Task(a.stat)
      for i in range(1, numMsgs + 1):
        (header, msg, octets) = a.retr(i)
        print "Message %d:" % i
        for line in msg:
          print '   ' + line
        print '-----------------------'
      yield gen.Task(a.quit)
    finally:
      a.close()
      callback()
  
  def finish():
    ioloop.IOLoop.instance().stop()
  
  main(finish)
  
  from tornado import ioloop
  ioloop.IOLoop.instance().start()
