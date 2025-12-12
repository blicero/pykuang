#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-11 16:50:05 krylon>
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
from threading import RLock

from pykuang import common
from pykuang.generator import ParallelGenerator


@dataclass(kw_only=True, slots=True)
class Nexus:
    """Nexus brings together all the moving parts, so to speak."""

    log: logging.Logger = field(default_factory=lambda: common.get_logger("nexus"))
    lock: RLock = field(default_factory=RLock)
    _active: bool = False
    pgen: ParallelGenerator = field(init=False)
    gcnt: int
    xcnt: int
    scnt: int

    def __post_init__(self) -> None:
        self.pgen = ParallelGenerator(cnt=self.gcnt)

    @property
    def active(self) -> bool:
        """Return the Nexus' active flag."""
        with self.lock:
            return self._active

    def start(self) -> None:
        """Let get this Nexus started!"""
        self.pgen.start()


# Local Variables: #
# python-indent: 4 #
# End: #
