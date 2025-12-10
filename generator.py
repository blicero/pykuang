#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-10 16:11:26 krylon>
#
# /data/code/python/pykuang/generator.py
# created on 09. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.generator

(c) 2025 Benjamin Walkenhorst
"""

import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address
from random import randint
from threading import RLock
from typing import Optional, Union

from dns.rcode import Rcode
from dns.resolver import (NXDOMAIN, Answer, LifetimeTimeout, NoNameservers,
                          Resolver)

from pykuang import common
from pykuang.blacklist import IPBlacklist, NameBlacklist
from pykuang.cache import Cache, CacheDB, CacheType
from pykuang.model import Host


@dataclass(kw_only=True, slots=True)
class HostGenerator:
    """HostGenerator generates random Hosts."""

    # I could let res be initialized by a default_factory, but I might want allow for configuring
    # custom recursive resolvers later on.
    log: logging.Logger = field(default_factory=lambda: common.get_logger("generator"))
    lock: RLock = field(default_factory=RLock)
    ipcache: CacheDB = field(init=False)
    bl_name: NameBlacklist = field(init=False)
    bl_addr: IPBlacklist = field(init=False)
    res: Resolver = field(init=False)

    def __post_init__(self) -> None:
        cache: Cache = Cache()
        self.ipcache = cache.get_db(CacheType.IPCache)
        self.res = Resolver()
        self.bl_addr = IPBlacklist.default()
        self.bl_name = NameBlacklist.default()

    def generate_ip(self, v6: bool = False) -> Union[IPv4Address, IPv6Address]:
        """Generate a random IP."""
        if v6:
            raise NotImplementedError("Generating IPv6 addresses is not implemented, yet.")

        octets: list[int] = []
        cnt: int = 0
        addr: Optional[Union[IPv4Address, IPv6Address]] = None

        with self.ipcache.tx(True) as tx:
            while addr is None:
                octets = [randint(0, 255) for x in range(4)]
                astr: str = ".".join([str(x) for x in octets])
                cnt += 1
                addr = ip_address(astr)
                if self.bl_addr.is_match(addr) or astr not in tx:
                    tx[astr] = "1"
                else:
                    addr = None

        self.log.debug("Generated IP %s in %d attempts.",
                       astr,
                       cnt)

        return addr

    def resolve_name(self, addr: Union[IPv4Address, IPv6Address]) -> Optional[str]:
        """Attempt to resolve an IP address into a hostname."""
        try:
            answer: Answer = self.res.resolve_address(str(addr))
            match answer.response.rcode():
                case Rcode.NOERROR if answer.rrset is not None:
                    return answer.rrset[0].to_text()
                case _:
                    self.log.error("Unexpected response code %s",
                                   answer.response.rcode())
        except NXDOMAIN as nx:
            # XXX After testing and debugging, I should disable/remove this log message.
            self.log.error("Couldn't resolve %s into hostname: %s",
                           addr,
                           nx)
        except NoNameservers as fail:
            self.log.error("Failed to get a response for %s from upstream resolver(s): %s",
                           addr,
                           fail)
        except LifetimeTimeout:
            pass
        return None

    def generate_host(self) -> Host:
        """Generate a random Host."""
        addr: Optional[Union[IPv4Address, IPv6Address]] = None
        name: Optional[str] = None

        while addr is None or name is None:
            addr = self.generate_ip()
            name = self.resolve_name(addr)
            if name is not None and self.bl_name.is_match(name):
                self.log.debug("Address %s resolves to %s, which is blacklisted.",
                               addr,
                               name)
                name = None

        host: Host = Host(name=name, addr=addr)
        return host


# Local Variables: #
# python-indent: 4 #
# End: #
