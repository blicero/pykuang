#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-26 18:21:38 krylon>
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
from pykuang.model import Host

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
class Scanner:
    """Scanner scans ports."""

    log: logging.Logger = field(default_factory=lambda: common.get_logger("scanner"))
    lock: RLock = field(default_factory=RLock)
    wcnt: int
    cmdQ: Queue[Message] = field(init=False)
    hostQ: Queue[Host] = field(init=False)
    interval: float = 2.0
    _active: bool = False

    def __post_init__(self) -> None:
        assert self.wcnt > 0
        self.cmdQ = Queue(self.wcnt * 2)
        self.hostQ = Queue(self.wcnt)

    @property
    def active(self) -> bool:
        """Return the Scanner's active flag."""
        with self.lock:
            return self._active

    def _feeder(self) -> None:
        db: Database = Database()
        try:
            while self.active:
                with self.lock:
                    cnt = self.wcnt
                hosts: list[Host] = db.host_get_random(cnt)
                for host in hosts:
                    self.hostQ.put(host)
                time.sleep(self.interval)
        finally:
            db.close()

    def _scan_worker(self, wid: int) -> None:
        self.log.debug("Scan worker %02d starting up.",
                       wid)

        while self.active:
            pass

# Local Variables: #
# python-indent: 4 #
# End: #
