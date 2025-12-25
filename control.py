#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-25 17:57:33 krylon>
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
from typing import Optional, Union


class Cmd(Enum):
    """Cmd represents a command to a Generator thread."""

    Start = auto()
    Stop = auto()
    Pause = auto()
    StartOne = auto()
    StopOne = auto()


class Facility(Enum):
    """Facility represents a subsystem of the application."""

    Generator = auto()
    XFR = auto()
    Scanner = auto()


@dataclass(kw_only=True, slots=True)
class Message:
    """Message is a message to be sent to a Generator thread."""

    Tag: Cmd
    Payload: Optional[Union[int, float, str, Facility]] = None


# Local Variables: #
# python-indent: 4 #
# End: #
