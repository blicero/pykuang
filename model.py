#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2026-01-05 14:48:19 krylon>
#
# /data/code/python/pykuang/model.py
# created on 05. 12. 2025
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

zone_pat: Final[re.Pattern] = re.compile("^[^.]+[.](.*)$")


class HostSource(IntEnum):
    """HostSource describes how we got knowledge of a Host."""

    User = auto()
    Generator = auto()
    XFR = auto()
    MX = auto()
    NS = auto()


@dataclass(slots=True, kw_only=True)
class Host:
    """Host is a system on the Internet."""

    host_id: int = -1
    name: str
    addr: Union[IPv4Address, IPv6Address]
    src: HostSource = HostSource.User
    added: datetime = field(default_factory=datetime.now)
    last_contact: Optional[datetime] = None
    sysname: str = ""
    location: str = ""
    xfr: bool = False

    @property
    def astr(self) -> str:
        """Return the Host's IP address as a string."""
        return str(self.addr)

    @property
    def zone(self) -> Optional[str]:
        """Return the DNS zone a host belongs to."""
        m = zone_pat.match(self.name)
        if m is None:
            return None
        return m[1]


@dataclass(kw_only=True, slots=True)
class Service:
    """Service is a service running on a Host."""

    sv_id: int = -1
    host_id: int
    port: int
    added: datetime
    response: Optional[str]


@dataclass(slots=True, kw_only=True)
class XFR:
    """XFR is the zone transfer of a DNS zone."""

    zone_id: int = -1
    name: str
    nameservers: list[str] = field(default_factory=list)
    added: datetime = field(default_factory=datetime.now)
    started: Optional[datetime] = None
    finished: Optional[datetime] = None
    status: bool = False


# Local Variables: #
# python-indent: 4 #
# End: #
