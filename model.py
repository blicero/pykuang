#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-20 17:43:45 krylon>
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


import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, auto
from ipaddress import IPv4Address, IPv6Address
from typing import Final, Optional, Union

from pykuang import common

zone_pat: Final[re.Pattern] = re.compile(r"^[^.]+[.](.*)$")


class HostSource(IntEnum):
    """HostSource is a symbolic constant to indicate how a How entered the database."""

    Generator = auto()
    MX = auto()
    NS = auto()
    XFR = auto()
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
    add_stamp: Optional[datetime] = None
    scan_stamp: Optional[datetime] = None

    @property
    def zone(self) -> str:
        """Return the Host's DNS zone."""
        z = zone_pat.findall(self.name)
        if len(z) == 0:
            return ""
        return z[0]


class XfrStatus(IntEnum):
    """XfrStatus represents the status of an attempted DNS zone transfer."""

    Blank = auto()
    Started = auto()
    Refused = auto()
    Duplicate = auto()
    Failed = auto()
    OK = auto()


@dataclass(slots=True, kw_only=True)
class Xfr:
    """Xfr represents a DNS zone transfer."""

    xid: int = -1
    zone: str
    begin: datetime
    end: Optional[datetime] = None
    status: XfrStatus = XfrStatus.Blank


bpat: Final[re.Pattern] = re.compile(r"^b'([^']+)'$")


@dataclass(slots=True, kw_only=True)
class Port:
    """Port represents a scanned Port. Duh."""

    pid: int = -1
    host_id: int
    port: int
    timestamp: datetime = field(default_factory=datetime.now)
    response: Optional[str] = None

    @property
    def stampstr(self) -> str:
        """Return a human readable string of the Port's timestamp."""
        return self.timestamp.strftime(common.TIME_FMT)

    @property
    def cleanresponse(self) -> str:
        """Return a slightly sanitized version of the Port's response."""
        res: str = "(NULL)"
        if self.response is not None:
            res = self.response

        m = bpat.search(self.response)
        if m is not None:
            res = m[1]
        return res.strip()


# Local Variables: #
# python-indent: 4 #
# End: #
