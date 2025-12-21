#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-21 22:18:38 krylon>
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
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from queue import Queue
from sqlite3 import IntegrityError
from threading import RLock, local
from typing import Final, Optional, Sequence, Union

import dns
from dns import rdatatype
from dns.exception import DNSException, Timeout
from dns.node import Node, NodeKind
from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.resolver import (NXDOMAIN, LifetimeTimeout, NoAnswer, NoNameservers,
                          Resolver)

from pykuang import common
from pykuang.blacklist import IPBlacklist, NameBlacklist
from pykuang.control import Message
from pykuang.database import Database, DBError
from pykuang.model import XFR, Host, HostSource


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
    name_blacklist: NameBlacklist = field(init=False)
    net_blacklist: IPBlacklist = field(init=False)
    pool: local = field(default_factory=local)

    def __post_init__(self) -> None:
        self.cmdQ = Queue(self.wcnt)
        self.xfrQ = Queue(self.wcnt)
        self.res = Resolver()
        self.name_blacklist = NameBlacklist.default()
        self.net_blacklist = IPBlacklist.default()

    @property
    def db(self) -> Database:
        """Return a database connection."""
        try:
            return self.pool.db
        except AttributeError:
            self.pool.db = Database()
            return self.pool.db

    @property
    def active(self) -> bool:
        """Return the client's active flag."""
        return self._active

    def resolve_name(self, name: str) -> Optional[Union[IPv4Address, IPv6Address]]:
        """Attempt to resolve a hostname to an IP address."""
        try:
            reply = self.res.resolve_name(name)
            for _atype, answer in reply.items():
                return ip_address(answer.rrset[0].address)
        except NXDOMAIN:
            pass
        return None

    def lookup_ns(self, xfr: XFR) -> Sequence[Union[str, IPv4Address, IPv6Address]]:
        """Attempt to look up the nameservers for a given zone."""
        try:
            servers: list[str] = []
            reply = self.res.resolve(xfr.name, rdatatype.NS)
            match reply.response.rcode():
                case Rcode.NOERROR if reply.rrset is not None:
                    for srv in reply.rrset:
                        addr: str = srv.to_text()
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

    def attempt_xfr(self, xfr: XFR, ns: str) -> bool:
        """Attempt to query <ns> for an XFR of <xfr>."""
        status: bool = False
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, xfr.name))
            now = datetime.now()

            for key, node in zone.nodes.items():
                name: str = key.to_text()
                if self.name_blacklist.is_match(name):
                    continue
                if node.classify() == NodeKind.REGULAR:
                    self._process_node(xfr.name, now, name, node)

            status = True
        except (EOFError, OSError) as terr:
            self.log.error("XFR of %s failed: %s",
                           xfr.name,
                           terr)
        except DNSException as cerr:
            self.log.error("XFR of %s failed: %s",
                           xfr.name,
                           cerr)

        return status

    def _process_node(self, zone: str, now: datetime, name: str, node: Node) -> None:
        db = self.db
        for rd in node.rdatasets:
            records = list(rd.items.keys())
            # self.log.debug("Handle Rdataset %s => %s",
            #                name,
            #                ", ".join([r.to_text() for r in records]))

            for r in records:
                match r.rdtype:
                    # XXX I need to assemble the name from the RDATA and the zone I am slurping,
                    #     so end up with useful hostnames instead of "ns1".
                    case RdataType.A | RdataType.AAAA:
                        if self.net_blacklist.is_match(r.address):
                            continue
                        h: Host = Host(name=f"{name}.{zone}",
                                       addr=ip_address(r.address),
                                       src=HostSource.XFR,
                                       added=now)
                        self.log.debug("Add Host %s/%s to database",
                                       h.name,
                                       h.addr)
                        if self.net_blacklist.is_match(h.addr) or \
                           self.name_blacklist.is_match(h.name):
                            continue
                        try:
                            with db:
                                db.host_add(h)
                        except IntegrityError:
                            continue
                    case RdataType.MX:
                        self.log.debug("Don't know how to handle MX records, yet.")
                    case RdataType.NS:
                        self.log.debug("Don't know how to handle NS records, yet.")

    def perform_xfr(self, xfr: XFR) -> bool:
        """Attempt a DNS zone transfer."""
        self.log.debug("Attempt XFR of %s", xfr.name)
        status: bool = False
        db = self.db
        try:
            with db:
                db.xfr_add(xfr)
            # First, we try to get the nameservers for the domain.
            nameservers = self.lookup_ns(xfr)

            if len(nameservers) == 0:
                self.log.debug("No nameservers were found for %s",
                               xfr.name)
                return False

            for ns in nameservers:
                self.log.debug("Querying %s for AXFR of %s",
                               ns,
                               xfr.name)
                addr = self.resolve_name(str(ns))
                if addr is None:
                    continue
                if self.attempt_xfr(xfr, str(addr)):
                    status = True
                    with db:
                        db.xfr_finish(xfr, True)
                    break
        except DBError as dberr:
            cname: Final[str] = dberr.__class__.__name__
            self.log.error("%s trying to AXFR %s: %s\n%s\n",
                           cname,
                           xfr.name,
                           dberr,
                           "\n".join(traceback.format_exception(dberr)))
        return status

# Local Variables: #
# python-indent: 4 #
# End: #
