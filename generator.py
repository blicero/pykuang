#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-11 18:08:46 krylon>
#
# /data/code/python/pykuang/generator.py
# created on 07. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.generator

(c) 2025 Benjamin Walkenhorst
"""


import dbm
import logging
from ipaddress import IPv4Address, IPv6Address, ip_address
from random import randbytes, random
from typing import Any, Final, Optional, Union

from dns import rdatatype
from dns.resolver import NXDOMAIN, Resolver

from pykuang import common
from pykuang.blacklist import (IPBlacklist, NameBlacklist, name_patterns,
                               reserved_networks)
from pykuang.model import Host, HostSource


class Generator:  # pylint: disable-msg=R0903
    """Generator cranks out random IP adresses, basically."""

    __slots__ = [
        "log",
        "cache",
        "name_blacklist",
        "net_blacklist",
        "v6_weight",
        "res",
    ]

    log: logging.Logger
    cache: Any
    name_blacklist: NameBlacklist
    net_blacklist: IPBlacklist
    v6_weight: float
    res: Resolver

    def __init__(self, cache_path: str = "", v6: float = 0.125) -> None:
        if cache_path == "":
            cache_path = common.path.ipcache()

        self.log = common.get_logger("generator")
        self.cache = dbm.open(cache_path, 'c', 0o644)
        self.name_blacklist = NameBlacklist(name_patterns)
        self.net_blacklist = IPBlacklist(reserved_networks)
        self.v6_weight = v6
        self.res = Resolver()

    def gen_ip(self) -> Union[IPv4Address, IPv6Address]:
        """Generate a random IP address."""
        cnt: int = 4
        if random() < self.v6_weight:
            self.log.debug("Generate IPv6 address.")
            cnt = 16

        addr: Union[IPv4Address, IPv6Address] = ip_address(randbytes(cnt))

        while (str(addr) in self.cache) or self.net_blacklist.match(addr):
            addr = ip_address(randbytes(cnt))
            # self.cache[str(addr)] = "True"

        self.cache[str(addr)] = "True"
        return addr

    def resolve_name(self, addr: Union[IPv4Address, IPv6Address]) -> Optional[str]:
        """Attempt to resolve an IP address into a hostname."""
        query: Final[str] = addr.reverse_pointer
        try:
            ans = self.res.resolve(query, rdatatype.PTR)
        except NXDOMAIN:
            return None

        if ans.rrset is None or len(ans.rrset) == 0:
            return None

        return ans.rrset[0].to_text()[:-1]

    def gen_host(self) -> Optional[Host]:
        """Attempt to generate a Host."""
        addr = self.gen_ip()
        name: Optional[str] = None

        while name is None or self.name_blacklist.match(name):
            name = self.resolve_name(addr)

        h: Host = Host(name=name, addr=addr, src=HostSource.Generator)
        return h


# Local Variables: #
# python-indent: 4 #
# End: #
