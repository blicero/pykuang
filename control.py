#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-13 15:39:02 krylon>
#
# /data/code/python/pykuang/control.py
# created on 13. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.control

(c) 2025 Benjamin Walkenhorst

This file contains data types for controlling worker threads in the various subsystems.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class Cmd(Enum):
    """Cmd represents a command to a Generator thread."""

    Stop = auto()
    Pause = auto()


@dataclass(kw_only=True, slots=True)
class Message:
    """Message is a message to be sent to a Generator thread."""

    Tag: Cmd
    Payload: Any = None


# Local Variables: #
# python-indent: 4 #
# End: #
