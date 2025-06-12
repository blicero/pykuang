#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-12 16:40:31 krylon>
#
# /data/code/python/pykuang/nexus.py
# created on 11. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.nexus

(c) 2025 Benjamin Walkenhorst
"""


import logging
import sys
import time
from threading import Lock, Thread

from pykuang import common
from pykuang.database import Database
from pykuang.generator import Generator
from pykuang.model import Host


class Nexus:
    """Nexus is where all the moving parts come together."""

    __slots__ = [
        "log",
        "db",
        "gen",
        "active_flag",
        "lock",
    ]

    log: logging.Logger
    db: Database
    gen: Generator
    active_flag: bool
    lock: Lock

    def __init__(self) -> None:
        self.log = common.get_logger("nexus")
        self.db = Database()
        self.gen = Generator()
        self.active_flag = False
        self.lock = Lock()

    @property
    def active(self) -> bool:
        """Return the state of the Nexus' active flag."""
        with self.lock:
            return self.active_flag

    def start(self) -> None:
        """Start the Nexus and its sub-components."""
        self.log.debug("Starting Nexus...")
        with self.lock:
            self.active_flag = True
            self.gen.start()
            gen_thr = Thread(target=self._gatherer, daemon=True)
            gen_thr.start()

    def stop(self) -> None:
        """Stop all the moving parts."""
        self.log.debug("Stopping Nexus...")
        with self.lock:
            self.active_flag = False
            self.gen.stop()

    def _gatherer(self) -> None:
        while self.active:
            h: Host = self.gen.queue.get()
            with self.db:
                self.db.host_add(h)
            self.log.debug("Got one Host from Generator: ID = %d, name = %s, addr = %s",
                           h.host_id,
                           h.name,
                           h.addr)


if __name__ == '__main__':
    nex = Nexus()
    nex.start()
    try:
        while nex.active:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Bye Bye")
        sys.exit(0)

# Local Variables: #
# python-indent: 4 #
# End: #
