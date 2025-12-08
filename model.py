#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-06 17:44:07 krylon>
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

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union


@dataclass(slots=True, kw_only=True)
class Host:
    """Host is a system on the Internet."""

    host_id: int = -1
    name: str
    addr: Union[IPv4Address, IPv6Address]
    added: datetime
    last_contact: Optional[datetime] = None
    sysname: str = ""
    location: str = ""


@dataclass(kw_only=True, slots=True)
class Service:
    """Service is a service running on a Host."""

    sv_id: int = -1
    host_id: int
    port: int
    added: datetime
    response: Optional[str]


@dataclass(slots=True, kw_only=True)
class Zone:
    """Zone is a DNS zone."""

    zone_id: int = -1
    name: str
    nameservers: list[str]
    xfr_stamp: datetime
    success: bool


# Local Variables: #
# python-indent: 4 #
# End: #
