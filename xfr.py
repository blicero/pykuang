#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-13 16:12:08 krylon>
#
# /data/code/python/pykuang/xfr.py
# created on 12. 12. 2025
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
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address
from queue import Queue
from threading import RLock
from typing import Union

from dns import rdatatype
from dns.exception import Timeout
from dns.rcode import Rcode
from dns.resolver import (NXDOMAIN, LifetimeTimeout, NoAnswer, NoNameservers,
                          Resolver)

from pykuang import common
from pykuang.control import Message
from pykuang.model import XFR


@dataclass(kw_only=True, slots=True)
class XFRClient:
    """XFR attempts to perform zone transfers."""

    log: logging.Logger = field(default_factory=lambda: common.get_logger("xfr"))
    lock: RLock = field(default_factory=RLock)
    _id_cnt: int = 0
    _active: bool = False
    wcnt: int = 4
    cmdQ: Queue[Message] = field(init=False)
    xfrQ: Queue[XFR] = field(init=False)
    res: Resolver = field(init=False)

    def __post_init__(self) -> None:
        self.cmdQ = Queue(self.wcnt)
        self.xfrQ = Queue(self.wcnt)
        self.res = Resolver()

    @property
    def active(self) -> bool:
        """Return the client's active flag."""
        return self._active

    def lookup_ns(self, xfr: XFR) -> list[Union[IPv4Address, IPv6Address]]:
        """Attempt to look up the nameservers for a given zone."""
        try:
            servers: list[Union[IPv4Address, IPv6Address]] = []
            reply = self.res.resolve(xfr.name, rdatatype.NS)
            match reply.response.rcode():
                case Rcode.NOERROR if reply.rrset is not None:
                    for srv in reply.rrset:
                        addr: Union[IPv4Address, IPv6Address] = ip_address(srv.to_text())
                        servers.append(addr)
                case _:
                    self.log.error("NS query for %s returned %s",
                                   xfr.name,
                                   reply.response.rcode().name)
        except NXDOMAIN as nx:
            # XXX After testing and debugging, I should disable/remove this log message.
            self.log.error("Couldn't find nameservers for %s: %s",
                           xfr.name,
                           nx)
        except NoNameservers as fail:
            self.log.error("Failed to get nameservers for %s: %s",
                           xfr.name,
                           fail)
        except LifetimeTimeout:
            pass
        except NoAnswer:
            pass
        except Timeout:
            pass
        return servers

    def perform_xfr(self, xfr: XFR) -> bool:
        """Attempt a DNS zone transfer."""
        self.log.debug("Attempt XFR of %s", xfr.name)
        return False


# Local Variables: #
# python-indent: 4 #
# End: #
