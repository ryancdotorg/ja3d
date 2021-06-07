#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import traceback

import os
import pwd
import grp
import signal
from stat import ST_SIZE

import logging
import argparse

import time
import json
import dpkt
import pcapy
import socket
import binascii

import ja3parse

from lru import LRU

from hashlib import md5

from exim import EximSocketProtocol

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

DEFAULT_PORTS = [25, 443, 465, 587, 993, 995]

# can't reopen a file once we chroot, so we watch for truncation and seek
class TruncatedFileHandler(logging.FileHandler):
    def __init__(self, filename, mode='a', encoding=None, delay=0):
        logging.FileHandler.__init__(self, filename, mode, encoding, delay)

    def emit(self, record):
        if self.stream:
            fd = self.stream.fileno()
            sres = os.fstat(fd)
            if sres[ST_SIZE] == 0:
                os.lseek(fd, 0, 0)

        logging.FileHandler.emit(self, record)

def setup_logger(logfile=None):
    global logger
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S%z',
    )
    logger = logging.getLogger('ja3d')
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING if logfile else logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if logfile:
        fh = TruncatedFileHandler('/var/log/ja3d/ja3d.log')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # set permissions
        fd = fh.stream.fileno()
        os.fchmod(fd, 0o0640)
        os.fchown(fd, 0, grp.getgrnam('adm')[2])

def build_filter(ports=None, direction=None):
    portfmt = '%s port %%u' % direction if direction else 'port %u'
    f  = 'tcp'
    if ports is not None:
        f += ' and ('
        #f += ' or '.join(map(lambda x: '%s port %u'%(direction or '',x), ports))
        f += ' or '.join(map(lambda x: portfmt % x, ports))
        f += ')'
    # tls record
    f += ' and tcp[((tcp[12:1] & 0xf0) >> 2):2] = 0x1603'
    # client hello
    f += ' and tcp[(((tcp[12:1] & 0xf0) >> 2)+5):1] = 0x01'
    return f

def convert_ip(value):
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)

def start_capture(devs, handler, filter):
    def _capture(p, dev):
        while os.getuid() == 0:
            time.sleep(0.01)
        logger.warning("Starting packet handling loop for %s" % dev)
        p.loop(-1, lambda h, d: reactor.callFromThread(handler, (dev, h, d)))

    reactor.callInThread(drop_privs)
    for dev in devs:
        p = pcapy.open_live(dev, 2048, 0, 100)
        p.setfilter(filter)
        logger.warning("Listening on %s: net=%s, mask=%s, linktype=%d" % \
              (dev, p.getnet(), p.getmask(), p.datalink()))
        reactor.callInThread(_capture, p, dev)

# basic lookup from an lru cache
class JA3(EximSocketProtocol):
    def __init__(self, lru):
        self.lru = lru

    def queryReceived(self, query):
        query = self.buf.rstrip().split('/')
        try:
            query_conn = query[0]+'/'+query[1]
            query_type = query[2] if len(query) > 2 else 'digest'
            if query_conn in self.lru:
                conn_data = self.lru[query_conn]
                if query_type == 'json':
                    self.sendResponse(json.dumps(conn_data))
                elif query_type == 'keyval':
                    ret = []
                    for k in conn_data:
                        ret.append(k+'='+conn_data[k])
                    self.sendResponse(' '.join(ret))
                elif query_type in conn_data:
                    self.sendResponse(conn_data[query_type])
                else:
                    logger.warning('bad query type: ' + query_type)
                    self.sendResponse('')
            else:
                logger.warning('not found: ' + query_conn)
                self.sendResponse('')
        except:
            logger.error(traceback.format_exc())
            self.sendResponse('')

class JA3Factory(Factory):
    def __init__(self, devs, ports=DEFAULT_PORTS, direction=None):
        # shared object for fingerprint data shared across clients
        bpf = build_filter(ports, direction)
        self.lru = LRU(2048)
        # set up the pcap in a thread, and register a callback for packets
        start_capture(devs, self._handler, bpf)

    # handle captured packet
    def _handler(self, tup):
        dev, hdr, data = tup

        # try to handle packet as ethernet
        try:
            eth = dpkt.ethernet.Ethernet(data)
        except Exception:
            eth = None

        # check whether we have ip data
        if eth is not None and isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
        else:
            # raw ip maybe?
            try:
                ip = dpkt.ip.IP(data)
            except:
                return None

        # try to parse as tcp
        if not isinstance(ip.data, dpkt.tcp.TCP):
            return None

        # pull out the payload
        tcp = ip.data
        tcp_data = tcp.data

        # we *should* have a tls client hello - try to parse it
        ja3 = ja3parse.ja3(tcp_data)
        if ja3 is None:
            return
        ja3_digest = md5(ja3.encode()).hexdigest()

        # save the result in the lru cache
        src_id = '%s/%u' % (convert_ip(ip.src), tcp.sport)
        self.lru[src_id] = {
            'dev': dev,
            'string': ja3,
            'digest': ja3_digest,
            'raw': binascii.hexlify(tcp_data)
        }

        logger.info('%s > %s:%d %s %s %s' % (
            src_id, dev, tcp.dport, ja3_digest, ja3,
            binascii.hexlify(tcp_data)
        ))

    # serve a connection
    def buildProtocol(self, addr):
        return JA3(self.lru)

def drop_privs():
    # need to get these values before chroot
    (uid, gid) = (pwd.getpwnam('nobody')[2], grp.getgrnam('nogroup')[2])

    # chroot does not change directory, we need to chdir first
    os.chdir('/var/empty')
    os.chroot('/var/empty')

    # set groups and verify (needs to be done before dropping root)
    os.setgroups([gid])
    os.setresgid(gid, gid, gid)
    g = os.getgroups()
    rgid, egid, sgid = os.getresgid()
    if rgid != gid or egid != gid or sgid != gid or len(g) != 1 or g[0] != gid:
        logger.critical('Failed to switch group!')
        os._exit(1)

    # set user and verify
    os.setresuid(uid, uid, uid)
    ruid, euid, suid = os.getresuid()
    if ruid != uid or euid != uid or suid != uid:
        logger.critical('Failed to switch user!')
        os._exit(1)

    logger.warning('Dropped privileges successfully.')

def main():
    desc = 'A python script for providing JA3 fingerprints to Exim'
    parser = argparse.ArgumentParser(description=(desc))
    help_text = 'Path for UNIX socket listener'
    parser.add_argument('-s', '--socket', required=True,
                        action='store', help=help_text)
    help_text = 'Interface to capture on'
    parser.add_argument('-i', '--interface', required=True,
                        action='append', help=help_text)
    help_text = 'Port to look for traffic on'
    parser.add_argument('-p', '--port', required=False,
                        action='append', help=help_text)
    help_text = 'Log file'
    parser.add_argument('-L', '--logfile', required=False,
                        action='store', help=help_text)
    args = parser.parse_args()

    setup_logger(logfile=args.logfile)

    # without the signal handler, ctrl-c doesn't work...
    def sig_handle(n, *args):
        logger.warning("Signal %u caught, exiting..." % n)
        reactor.stop()
        os._exit(0)

    # set up signal handlers
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, sig_handle)

    # start everything up
    factory = JA3Factory(args.interface)
    reactor.listenUNIX(args.socket, factory, mode=0o0600, wantPID=True)
    os.chown(args.socket, -1, grp.getgrnam('Debian-exim')[2])
    os.chmod(args.socket, 0o0660)
    reactor.run()

if __name__ == "__main__":
    main()
