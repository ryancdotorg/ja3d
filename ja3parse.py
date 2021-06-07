#!/usr/bin/env python

import dpkt
import struct
from hashlib import md5

__author__ = "Tommy Stallings"
__copyright__ = "Copyright (c) 2017, salesforce.com, inc."
__credits__ = ["John B. Althouse", "Jeff Atkinson", "Josh Atkins"]
__license__ = "BSD 3-Clause License"
__version__ = "1.0.0"
__maintainer__ = "Tommy Stallings, Brandon Dixon"
__email__ = "tommy.stallings@salesforce.com"

_TLS_HANDSHAKE = 22
_GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                 0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                 0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                 0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# _GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00


def _parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


def _ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def _convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = _ntoh(data[i: i + element_width])
        if element not in _GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def _process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if not _GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = _parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = _convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = _parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = _convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results

def ja3_digest(tcp_data):
    r = ja3(tcp_data)
    if r is None:
        return r
    else:
        return md5(r.encode()).hexdigest()

def ja3(tcp_data):
    records = list()

    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(tcp_data)
    except dpkt.ssl.SSL3Exception:
        return None
    except dpkt.dpkt.NeedData:
        return None

    if len(records) <= 0:
        return None

    for record in records:
        if record.type != _TLS_HANDSHAKE:
            continue
        if len(record.data) == 0:
            continue
        client_hello = bytearray(record.data)
        if client_hello[0] != 1:
            # We only want client HELLO
            continue
        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except dpkt.dpkt.NeedData:
            # Looking for a handshake here
            continue
        if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
            # Still not the HELLO
            continue

        client_handshake = handshake.data
        buf, ptr = _parse_variable_array(client_handshake.data, 1)
        buf, ptr = _parse_variable_array(client_handshake.data[ptr:], 2)
        ja3 = [str(client_handshake.version)]

        # Cipher Suites (16 bit values)
        ja3.append(_convert_to_ja3_segment(buf, 2))
        ja3 += _process_extensions(client_handshake)
        ja3 = ",".join(ja3)
        return ja3

    return None
