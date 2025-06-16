#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-16 22:35:23 krylon>
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
from queue import Queue
from threading import Lock, local
from typing import Final, Optional

from pykuang import common
from pykuang.config import Config
from pykuang.database import Database
from pykuang.model import Host, HostSource

www_pat: Final[re.Pattern] = re.compile("^www", re.I)

interesting_ports: Final[list[int]] = [
    21,
    22,
    23,
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
        self.scanq = Queue()
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
        db = self.db
        while self.active:
            hosts = db.host_get_random(self.cnt)
            for h in hosts:
                self.log.debug("Looking for scannable port for Host %d, aka %s (%s)",
                               h.host_id,
                               h.name,
                               h.addr)
                plist = db.port_get_by_host(h)
                ports: set[int] = {p.port for p in plist}  # noqa: F841
                target: int = self.get_scan_port(h, plist)
                self.scanq.put((h, target))

    def _worker(self, wid: int) -> None:
        while self.active:
            try:
                scan_tuple = self.scanq.get(timeout=10)
            except Empty:
                continue
            else:
                pass

    def scan_tcp_generic(self, host: Host, port: Port) -> bool:
        """Attempt to establish a TCP connection to the given host and port."""
        try:
            af: socket.AddressFamily = socket.AF_INET
            if isinstance(host.addr, IPv6Address):
                af = socket.AF_INET6
            # Nah, that isn't quite right, is it?
            # Go makes that so much easier... Just sayin'
        except OSError as err:
            self.log.error("Failed to connect to %s:%d - %s",
                           host.addr,
                           port.port,
                           err)

# Local Variables: #
# python-indent: 4 #
# End: #
