#!/usr/bin/env python

from zope.interface import implementer
from twisted.internet.interfaces import IHalfCloseableProtocol
from twisted.internet.protocol import Protocol

@implementer(IHalfCloseableProtocol)
class EximSocketProtocol(Protocol):
    # buffer received data
    def dataReceived(self, data):
        if not hasattr(self, 'buf'):
            self.buf = ''
        self.buf += data

    # write response and close socket
    def sendResponse(self, response):
        self.transport.write(response)
        self.transport.loseConnection()

    # needs to call sendResponse
    def queryReceived(self, query):
        raise NotImplementedError

    # exim signals end of query by half-closing the connection
    def readConnectionLost(self):
        self.queryReceived(self.buf)
