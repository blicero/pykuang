#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-14 00:07:58 krylon>
#
# /data/code/python/pykuang/xfr.py
# created on 12. 06. 2025
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
from datetime import datetime
from ipaddress import ip_address
from queue import Queue, ShutDown
from threading import Lock, Thread, local
from typing import Final

import dns.query
import dns.resolver
import dns.zone
from dns.exception import DNSException
from dns.node import Node, NodeKind
from dns.rdatatype import RdataType

from pykuang import common
from pykuang.database import Database, DBLockError, IntegrityError
from pykuang.model import Host, HostSource, Xfr, XfrStatus


class XFRClient:
    """XFRClient attempts to initiate zone transfers (aka XFRs)."""

    __slots__ = [
        "log",
        "loc",
        "queue",
        "lock",
        "_active",
    ]

    log: logging.Logger
    loc: local
    queue: Queue
    lock: Lock
    _active: bool

    def __init__(self) -> None:
        self.log = common.get_logger("xfr")
        self.loc = local()
        self.queue = Queue()
        self.lock = Lock()
        self._active = False

    @property
    def db(self) -> Database:
        """Return a thread-local database connection."""
        try:
            return self.loc.db
        except AttributeError:
            self.loc.db = Database()
            return self.loc.db

    @property
    def active(self) -> bool:
        """Return the Client's active flag."""
        with self.lock:
            return self._active

    def start(self, cnt: int) -> None:
        """Start the XFR client."""
        with self.lock:
            self._active = True
            for _ in range(cnt):
                thr = Thread(target=self._run, daemon=True)
                thr.start()

    def stop(self) -> None:
        """Clear the XFRClient's active flag."""
        with self.lock:
            self._active = False
            self.queue.shutdown()

    def _run(self) -> None:
        while self.active:
            try:
                zone: str = self.queue.get()
            except ShutDown:
                return
            with self.db:
                try:
                    req = self.db.xfr_add(zone)
                except DBLockError:
                    self.queue.put(zone)
                    return
                except IntegrityError:
                    continue
                assert req is not None
                self.log.debug("About to start XFRing zone %s (%d)", req.zone, req.xid)
                self._perform_xfr(req)

    def _perform_xfr(self, zone: Xfr) -> bool:
        self.log.debug("Attempting XFR of zone %s", zone.zone)
        try:
            soa_answer = dns.resolver.resolve(zone.zone, "SOA")
            master_answer = dns.resolver.resolve(soa_answer[0].mname, "A")
        except DNSException as dnserr:
            self.log.debug("XFR of %s failed: %s",
                           zone.zone,
                           dnserr)
            return False

        db = self.db

        req = db.xfr_get_by_zone(zone.zone)
        if req is not None:
            return False

        now: Final[datetime] = datetime.now()
        status: XfrStatus = XfrStatus.Blank

        # XXX This code is a monstrosity, I really should decompose it into smaller chunks,
        #     if only for the indentation depth.

        try:
            z = dns.zone.from_xfr(dns.query.xfr(master_answer[0].address, zone.zone))
            status = XfrStatus.Started
            for key, node in z.nodes.items():
                name: str = key.to_text()
                if node.classify() == NodeKind.REGULAR:
                    self._process_node(now, name, node)
            status = XfrStatus.OK
        except DNSException as err:
            self.log.error("XFR of %s failed: %s",
                           zone.zone,
                           err)
            status = XfrStatus.Refused
        except ConnectionResetError as rerr:
            self.log.error("XFR of %s failed: %s",
                           zone.zone,
                           rerr)
            status = XfrStatus.Refused
        finally:
            db.xfr_end(zone, status)
        return status == XfrStatus.OK

    def _process_node(self, now: datetime, name: str, node: Node) -> None:
        db = self.db
        for rd in node.rdatasets:
            records = list(rd.items.keys())
            # self.log.debug("Handle Rdataset %s => %s",
            #                name,
            #                ", ".join([r.to_text() for r in records]))

            for r in records:
                match r.rdtype:
                    case RdataType.A | RdataType.AAAA:
                        h: Host = Host(name=name,
                                       addr=ip_address(r.address),
                                       src=HostSource.XFR,
                                       add_stamp=now)
                        self.log.debug("Add Host %s/%s to database",
                                       h.name,
                                       h.addr)
                        db.host_add(h)
                    case RdataType.MX:
                        self.log.debug("Don't know how to handle MX records, yet.")
                    case RdataType.NS:
                        self.log.debug("Don't know how to handle NS records, yet.")

# Local Variables: #
# python-indent: 4 #
# End: #
