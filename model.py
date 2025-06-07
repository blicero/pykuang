#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-07 16:16:00 krylon>
#
# /data/code/python/pykuang/model.py
# created on 07. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.model

(c) 2025 Benjamin Walkenhorst
"""


from dataclasses import dataclass
from enum import IntEnum, auto
from ipaddress import IPv4Address, IPv6Address
from typing import Union


class HostSource(IntEnum):
    """HostSource is a symbolic constant to indicate how a How entered the database."""

    Generator = auto()
    MX = auto()
    NS = auto()
    User = auto()


@dataclass(slots=True, kw_only=True)
class Host:
    """Host is a system, real or virtual, somewhere on the Internet."""

    host_id: int = -1
    name: str
    addr: Union[IPv4Address, IPv6Address, str]
    src: HostSource
    location: str = ""
    os: str = ""

# Local Variables: #
# python-indent: 4 #
# End: #
