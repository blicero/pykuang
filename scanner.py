#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-15 16:58:45 krylon>
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
from queue import Queue
from threading import Lock, local

from pykuang import common
from pykuang.database import Database


class Scanner:
    """Scanner scans ports. Duh. Aren't you sorry you asked?"""

    __slots__ = [
            "log",
            "loc",
            "lock",
            "scanq",
            "_active",
    ]

    log: logging.Logger
    loc: local
    lock: Lock
    scanq: Queue
    _active: bool

    def __init__(self) -> None:
        self.log = common.get_logger("scanner")
        self.loc = local()
        self.lock = Lock()
        self.scanq = Queue()
        self._active = False

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


# Local Variables: #
# python-indent: 4 #
# End: #
