#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-12 22:30:33 krylon>
#
# /data/code/python/pykuang/xfr.py
# created on 12. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.xfr

(c) 2025 Benjamin Walkenhorst
"""


import logging
from queue import Queue
from threading import Lock, local

from pykuang import common
from pykuang.database import Database


class XFRClient:
    """XFRClient attempts to initiate zone transfers (aka XFRs)."""

    __slots__ = [
        "log",
        "loc",
        "queue",
        "lock",
        "_active",
    ]

    log: logging.Logger
    loc: local
    queue: Queue
    lock: Lock
    _active: bool

    def __init__(self) -> None:
        self.log = common.get_logger("xfr")
        self.loc = local()
        self.queue = Queue()
        self.lock = Lock()
        self._active = False

    @property
    def db(self) -> Database:
        """Return a thread-local database connection."""
        try:
            return self.loc.db
        except AttributeError:
            self.loc.db = Database()
            return self.loc.db

    @property
    def active(self) -> bool:
        """Return the Client's active flag."""
        with self.lock:
            return self._active

    def _run(self) -> None:
        while self.active:
            zone: str = self.queue.get()
            with self.db:
                xfr = self.db.xfr_add(zone)
                assert xfr is not None
                self.log.debug("About to start XFRing zone %s (%d)", xfr.zone, xfr.xid)


# Local Variables: #
# python-indent: 4 #
# End: #
