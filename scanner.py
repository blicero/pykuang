#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-20 17:48:59 krylon>
#
# /data/code/python/pykuang/scanner.py
# created on 15. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.scanner

(c) 2025 Benjamin Walkenhorst
"""


import logging
import random
import re
import socket
import time
from ipaddress import IPv4Address, IPv6Address
from queue import Empty, Queue, ShutDown
from threading import Lock, Thread, local
from typing import Final, Optional, Union

import requests
from dns.exception import DNSException
from dns.resolver import Resolver

from pykuang import common
from pykuang.config import Config
from pykuang.database import Database
from pykuang.model import Host, HostSource, Port


def get_af(addr: Union[IPv4Address, IPv6Address]) -> socket.AddressFamily:  # noqa: E501 # pylint: disable-msg=E0611,E1101
    """Get the appropriate address family for the given IP address."""
    if isinstance(addr, IPv4Address):
        return socket.AF_INET
    return socket.AF_INET6


# telnet_probe: Final[list[int]] = [
#     0xff, 0xfc, 0x25,  # Won't Authentication
#     0xff, 0xfd, 0x03,  # Do Suppress Go Ahead
#     0xff, 0xfc, 0x18,  # Won't Terminal Type
#     0xff, 0xfc, 0x1f,  # Won't Window Size
#     0xff, 0xfc, 0x20,  # Won't Terminal Speed
#     0xff, 0xfb, 0x22,  # Will Linemode
# ]

www_pat: Final[re.Pattern] = re.compile("^www", re.I)
byte_pat: Final[re.Pattern] = re.compile(r"^b'([^']*)'$")

interesting_ports: Final[list[int]] = [
    21,
    22,
    # 23,
    25,
    53,
    79,
    80,
    110,
    143,
    161,
    443,
    631,
    1024,
    4444,
    2525,
    5353,
    5800,
    5900,
    8000,
    8080,
    8081,
]

default_data: Final[bytes] = b"Wer das liest, ist doof.\n"
http_agent: Final[str] = \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " + \
    "Chrome/113.0.0.0 Safari/537.36"


class Scanner:
    """Scanner scans ports. Duh. Aren't you sorry you asked?"""

    __slots__ = [
        "log",
        "loc",
        "lock",
        "scanq",
        "_active",
        "cnt",
    ]

    log: logging.Logger
    loc: local
    lock: Lock
    scanq: Queue
    _active: bool
    cnt: int

    def __init__(self, cnt: int = 0) -> None:
        self.log = common.get_logger("scanner")
        self.loc = local()
        self.lock = Lock()
        self.scanq = Queue(max(int(cnt/2), 2))
        self._active = False

        if cnt == 0:
            cfg: Config = Config()
            try:
                self.cnt = cfg.get("Scanner", "Parallel")
            except:  # noqa: E722,B001 pylint: disable-msg=W0702
                self.cnt = 8

    @property
    def active(self) -> bool:
        """Return the Scanner's active flag."""
        with self.lock:
            return self._active

    @property
    def db(self) -> Database:
        """Return a connection to the Database."""
        try:
            return self.loc.db
        except AttributeError:
            self.loc.db = Database()
            return self.loc.db

    def start(self) -> None:
        """Start the Scanner."""
        self.log.debug("Scanner starting up...")
        with self.lock:
            self._active = True
        fthr = Thread(target=self._feeder, daemon=True)
        fthr.start()

        self.log.debug("Starting %d scanner workers",
                       self.cnt)
        for i in range(self.cnt):
            wthr = Thread(target=self._worker,
                          daemon=True,
                          name=f"ScanWorker{i+1:02d}",
                          args=(i+1, ))
            wthr.start()

    def stop(self) -> None:
        """Clear the Scanner's active flag, shutdown the queue."""
        with self.lock:
            self._active = False
            self.scanq.shutdown()

    def get_scan_port(self, host: Host, ports: set[int]) -> Optional[int]:
        """Get a semi-random port to scan on the given Host."""
        match host.src:
            case HostSource.MX:
                if 25 not in ports:
                    return 25
                if 110 not in ports:
                    return 110
                if 143 not in ports:
                    return 143
            case HostSource.NS if 53 not in ports:
                return 53

        if www_pat.match(host.name) is not None:
            if 80 not in ports:
                return 80
            if 443 not in ports:
                return 443

        plist = [p for p in interesting_ports if p not in ports]
        if plist is None or len(plist) == 0:
            return None

        return random.choice(plist)

    def _feeder(self) -> None:
        self.log.debug("Feeder Thread starting up.")
        db = self.db
        try:
            while self.active:
                hosts = db.host_get_random(self.cnt)
                for h in hosts:
                    self.log.debug("Looking for scannable port for Host %d, aka %s (%s)",
                                   h.host_id,
                                   h.name,
                                   h.addr)
                    plist = db.port_get_by_host(h)
                    ports: set[int] = {p.port for p in plist}  # noqa: F841
                    target: Optional[int] = self.get_scan_port(h, ports)
                    if target is not None:
                        self.log.debug("Attempting to scan Host %s (%s) Port %d",
                                       h.name,
                                       h.addr,
                                       target)
                        try:
                            self.scanq.put((h, target))
                        except ShutDown:
                            return
                time.sleep(1.0)
        finally:
            self.log.debug("Feeder thread says bye bye")

    def _worker(self, wid: int) -> None:
        self.log.debug("Scanner Worker %d starting up", wid)
        try:
            while self.active:
                try:
                    scan_tuple = self.scanq.get(timeout=10)
                    p = Port(host_id=scan_tuple[0].host_id,
                             port=scan_tuple[1])
                    result: bool = False

                    match scan_tuple[1]:
                        case 80 | 443 | 8080 | 8081 | 1024:
                            result = self.scan_http(scan_tuple[0], p)
                        case 53:
                            result = self.scan_dns(scan_tuple[0], p)
                        case _:
                            result = self.scan_tcp_generic(scan_tuple[0], p)
                except Empty:
                    continue
                except ShutDown:
                    return
                except Exception as err:  # pylint: disable-msg=W0718
                    self.log.error("Unhandled %s while scanning host: %s",
                                   err.__class__.__name__,
                                   err)
                    continue
                else:
                    self.log.debug("Scanned %s:%d - %s (%s)",
                                   scan_tuple[0].addr,
                                   p.port,
                                   p.response,
                                   result)
                    with self.db:
                        self.db.port_add(p)
        finally:
            self.log.debug("Scanner Worker %d says toodles!", wid)

    def scan_tcp_generic(self, host: Host, port: Port) -> bool:
        """Attempt to establish a TCP connection to the given host and port."""
        try:
            conn = socket.create_connection((str(host.addr), port.port))
            conn.send(default_data)
            response = conn.recv(4096)
        except OSError as err:
            self.log.error("Failed to connect to %s:%d - %s",
                           host.addr,
                           port.port,
                           err)
            return False
        # TODO Clean up response strings like b'blablabla'
        port.response = str(response)
        m = byte_pat.search(port.response)
        if m is not None:
            port.response = m[1].strip()
        return True

    def scan_http(self, host: Host, port: Port) -> bool:
        """Attempt to send a HTTP HEAD request to the given target."""
        try:
            schema = "https" if port.port == 443 else "http"
            scan_url = f"{schema}://{host.addr}:{port.port}/"
            headers = {
                "host": host.name,
                "agent": http_agent,
            }
            res = requests.head(scan_url, headers=headers, timeout=5.0)
        except (requests.RequestException,
                requests.ConnectionError,
                requests.HTTPError,
                requests.Timeout) as err:
            self.log.error("Failed to scan %s: %s",
                           scan_url,
                           err)
            return False
        port.response = res.headers["server"]
        return True

    def scan_dns(self, h: Host, p: Port) -> bool:
        """Attempt to scan a DNS Server."""
        res: Resolver = Resolver("", False)
        res.nameservers = [str(h.addr)]

        try:
            ans = res.resolve("version.bind", "TXT", "CH")
        except DNSException:
            return False

        if ans.rrset is None or len(ans.rrset) == 0:
            return False

        name: str = ans.rrset[0].to_text()
        p.response = name
        return True

    # Dienstag, 17. 06. 2025, 18:27
    # The hand-rolled telnet probe I did in C and Go is WAY too complex,
    # I do not feel like re-implementing that beast in Python right about now,
    # and I also don't want to drag in another dependency at this time.
    # Python used to have telnetlib in the standard library, but that has been
    # removed as of 3.13.
    # def scan_telnet(self, host: Host, port: Port) -> bool:
    #     """Attempt to scan a telnet server."""
    #     try:
    #         conn = socket.create_connection((str(host.addr), port.port))
    #         conn.send(bytes(telnet_probe))


# Local Variables: #
# python-indent: 4 #
# End: #
