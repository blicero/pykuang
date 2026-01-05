#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2026-01-05 15:45:54 krylon>
#
# /data/code/python/pykuang/nexus.py
# created on 11. 12. 2025
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
from dataclasses import dataclass, field
from queue import Queue
from threading import RLock

from pykuang import common
from pykuang.control import Facility, Message
from pykuang.generator import ParallelGenerator
from pykuang.scanner import Scanner
from pykuang.xfr import XFRProcessor


@dataclass(kw_only=True, slots=True)
class Nexus:
    """Nexus brings together all the moving parts, so to speak."""

    log: logging.Logger = field(default_factory=lambda: common.get_logger("nexus"))
    lock: RLock = field(default_factory=RLock)
    _active: bool = False
    cmdQ: Queue[Message] = field(init=False)
    pgen: ParallelGenerator = field(init=False)
    pxfr: XFRProcessor = field(init=False)
    pscn: Scanner = field(init=False)
    gcnt: int
    xcnt: int
    scnt: int

    def __post_init__(self) -> None:
        assert self.gcnt > 0
        assert self.xcnt > 0
        assert self.scnt > 0

        self.cmdQ = Queue()
        self.pgen = ParallelGenerator(wcnt=self.gcnt)
        self.pxfr = XFRProcessor(wcnt=self.xcnt)
        self.pscn = Scanner(wcnt=self.scnt)

    @property
    def active(self) -> bool:
        """Return the Nexus' active flag."""
        with self.lock:
            return self._active

    def start(self) -> None:
        """Let get this Nexus started!"""
        with self.lock:
            self._active = True
        self.pxfr.start()
        self.pgen.start()
        self.pscn.start()

    def stop(self) -> None:
        """Tell all subsystems to stop."""
        with self.lock:
            self._active = True
        self.pxfr.stop()
        self.pgen.stop()
        self.pscn.stop()

    def start_one(self, subsystem: Facility) -> None:
        """Start a single worker thread in the specified subsystem."""
        self.log.debug("Start one %s thread.",
                       subsystem.name)
        match subsystem:
            case Facility.Generator:
                self.pgen.start_one()
            case Facility.XFR:
                self.pxfr.start_one()
            case Facility.Scanner:
                self.pscn.start_one()

    def stop_one(self, subsystem: Facility) -> None:
        """Stop one worker thread in the specified subsystem."""
        self.log.debug("Stop one %s thread.",
                       subsystem.name)
        match subsystem:
            case Facility.Generator:
                self.pgen.stop_one()
            case Facility.XFR:
                self.pxfr.stop_one()
            case Facility.Scanner:
                self.pscn.stop_one()

# Local Variables: #
# python-indent: 4 #
# End: #
