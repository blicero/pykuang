#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-12 18:22:07 krylon>
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

from pykuang import common
from pykuang.database import Database


class XFRClient:
    """XFRClient attempts to initiate zone transfers (aka XFRs)."""

    __slots__ = [
        "log",
        "db",
        "queue",
    ]

    log: logging.Logger
    db: Database
    queue: Queue

    def __init__(self) -> None:
        self.log = common.get_logger("xfr")
        self.db = Database()
        self.queue = Queue()


# Local Variables: #
# python-indent: 4 #
# End: #
