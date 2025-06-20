#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-20 17:51:28 krylon>
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
from queue import ShutDown
from threading import Lock, Thread

from pykuang import common
from pykuang.config import Config
from pykuang.database import Database, DBLockError, IntegrityError
from pykuang.generator import Generator
from pykuang.model import Host
from pykuang.scanner import Scanner
from pykuang.web import WebUI
from pykuang.xfr import XFRClient


class Nexus:
    """Nexus is where all the moving parts come together."""

    __slots__ = [
        "log",
        "db",
        "gen",
        "active_flag",
        "lock",
        "xc",
        "sc",
        "cnt_gen",
        "cnt_xfr",
        "cnt_scan",
        "do_gen",
        "do_xfr",
        "do_scan",
        "do_www",
        "www",
    ]

    log: logging.Logger
    db: Database
    gen: Generator
    active_flag: bool
    lock: Lock
    xc: XFRClient
    sc: Scanner
    cnt_gen: int
    cnt_xfr: int
    cnt_scan: int
    do_gen: bool
    do_xfr: bool
    do_scan: bool
    do_www: bool
    www: WebUI

    def __init__(self) -> None:
        cfg = Config()
        gen_cnt = cfg.get("Generator", "Parallel")
        xfr_cnt = cfg.get("XFR", "Parallel")
        self.do_gen = cfg.get("Generator", "Active")
        self.do_xfr = cfg.get("XFR", "Active")
        self.do_scan = cfg.get("Scanner", "Active")
        self.do_www = cfg.get("Web", "Active")

        self.log = common.get_logger("nexus")
        self.db = Database()
        self.gen = Generator()
        self.active_flag = False
        self.lock = Lock()
        self.xc = XFRClient()
        self.sc = Scanner()
        self.cnt_gen = gen_cnt
        self.cnt_xfr = xfr_cnt
        self.www = WebUI()

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
        if self.do_gen:
            self.gen.start(self.cnt_gen)
            gen_thr = Thread(target=self._gatherer, daemon=True)
            gen_thr.start()
        if self.do_xfr:
            self.xc.start(self.cnt_xfr)
        if self.do_scan:
            self.sc.start()
        if self.do_www:
            www_thr = Thread(target=self.www.run, daemon=True)
            www_thr.start()

    def stop(self) -> None:
        """Stop all the moving parts."""
        self.log.debug("Stopping Nexus...")
        with self.lock:
            self.active_flag = False
            self.gen.stop()
            self.sc.stop()
            self.xc.stop()

    def _gatherer(self) -> None:
        while self.active:
            try:
                h: Host = self.gen.queue.get()
            except ShutDown:
                return
            with self.db:
                try:
                    self.db.host_add(h)
                except DBLockError:
                    self.gen.queue.put(h)
                    continue
                except IntegrityError as ierr:
                    self.log.error("Failed to add host %s (%s) to database: %s",
                                   h.name,
                                   h.addr,
                                   ierr)
                z: str = h.zone
                if z != "":
                    try:
                        self.xc.queue.put(z)
                    except ShutDown:
                        return
            # self.log.debug("Got one Host from Generator: ID = %d, name = %s, addr = %s",
            #                h.host_id,
            #                h.name,
            #                h.addr)


if __name__ == '__main__':
    nex = Nexus()
    nex.start()
    try:
        while nex.active:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Bye Bye")
        nex.stop()
        sys.exit(0)

# Local Variables: #
# python-indent: 4 #
# End: #
