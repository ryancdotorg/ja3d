#!/usr/bin/env python

from exim import EximSocketProtocol
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

class EximPotato(EximSocketProtocol):
    def queryReceived(self, query):
        self.sendResponse(query[::-1])

def main():
    factory = Factory()
    factory.protocol = EximPotato
    reactor.listenTCP(9999, factory, interface='127.0.0.1')
    reactor.run()

if __name__ == "__main__":
    main()
