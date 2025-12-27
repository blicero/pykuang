#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-27 15:46:19 krylon>
#
# /data/code/python/pykuang/scanner.py
# created on 26. 12. 2025
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
import time
from dataclasses import dataclass, field
from queue import Queue
from threading import RLock
from typing import Final

from pykuang import common
from pykuang.control import Message
from pykuang.database import Database
from pykuang.model import Host, Service

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
    220,
    389,
    443,
    1433,  # MSSQL
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    5900,
    8080,
]


@dataclass(kw_only=True, slots=True)
class ScanRequest:
    """ScanRequest wraps a Host and a port to scan."""

    host: Host
    port: int

    def __post_init__(self) -> None:
        assert 0 < self.port < 65536, "Port must be a number between 1 and 65535"


@dataclass(kw_only=True, slots=True)
class ScanResult:
    """ScanResult is the result scanning a port."""

    host: Host
    result: Service


@dataclass(kw_only=True, slots=True)
class Scanner:
    """Scanner scans ports."""

    log: logging.Logger = field(default_factory=lambda: common.get_logger("scanner"))
    lock: RLock = field(default_factory=RLock)
    wcnt: int
    cmdQ: Queue[Message] = field(init=False)
    scanQ: Queue[ScanRequest] = field(init=False)
    resQ: Queue[ScanResult] = field(init=False)
    interval: float = 2.0
    _active: bool = False

    def __post_init__(self) -> None:
        assert self.wcnt > 0
        self.cmdQ = Queue(self.wcnt * 2)
        self.scanQ = Queue(self.wcnt)
        self.resQ = Queue(self.wcnt * 2)

    @property
    def active(self) -> bool:
        """Return the Scanner's active flag."""
        with self.lock:
            return self._active

    def _feeder(self) -> None:
        self.log.debug("Feeder thread is coming up...")
        db: Database = Database()
        try:
            while self.active:
                with self.lock:
                    cnt = self.wcnt
                hosts: list[Host] = db.host_get_random(cnt)
                for host in hosts:
                    req = self._select_port(db, host)
                    self.scanQ.put(req)
                time.sleep(self.interval)
        finally:
            db.close()
            self.log.debug("Feeder thread is quitting.")

    def _gatherer(self) -> None:
        """Gather scanned ports and store them in the database."""
        self.log.debug("Gatherer threads is starting up.")
        db: Final[Database] = Database()
        try:
            while self.active:
                pass
        finally:
            db.close()
            self.log.debug("Gatherer thread is quitting.")

    def _scan_worker(self, wid: int) -> None:
        self.log.debug("Scan worker %02d starting up.",
                       wid)
        while self.active:
            pass

    def _select_port(self, _db: Database, host: Host) -> ScanRequest:
        """Pick a port to scan for <host>."""
        #  scanned_ports: list[Service] = db.service_get_by_host(host)
        return ScanRequest(host=host, port=22)

# Local Variables: #
# python-indent: 4 #
# End: #
