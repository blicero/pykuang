#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2026-01-02 17:26:46 krylon>
#
# /data/code/python/pykuang/scanner.py
# created on 26. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.scanner

(c) 2025 Benjamin Walkenhorst
"""


import logging
import random
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from queue import Queue
from threading import RLock
from typing import Final, NamedTuple, Optional, Union

import dns
import requests
from dns.resolver import Resolver
from telnetlib3 import Telnet  # type: ignore # pylint: disable-msg=E0401

from pykuang import common
from pykuang.control import Message
from pykuang.database import Database
from pykuang.model import Host, HostSource, Service

conn_timeout: Final[float] = 2.5
rcv_buf: Final[int] = 256

interesting_ports: Final[list[int]] = [
    21,
    22,
    23,
    25,
    53,
    79,
    80,
    110,
    143,
    161,
    220,
    389,
    443,
    1433,  # MSSQL
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    5900,
    8080,
]


@dataclass(kw_only=True, slots=True)
class ScanTarget:
    """ScanTarget is an IP address and a port number to scan."""

    addr: Union[str, IPv4Address, IPv6Address]
    port: int

    def __post_init__(self) -> None:
        if not 0 < self.port < 65536:
            raise ValueError(f"Invalid port {self.port}")

    @property
    def astr(self) -> str:
        """Return the address as a string."""
        if isinstance(self.addr, (IPv4Address, IPv6Address)):
            return str(self.addr)
        return self. addr


class ScanReply(NamedTuple):
    """ScanReply is simply a reply from an attempted scan."""

    status: bool
    response: str


@dataclass(kw_only=True, slots=True)
class ScanRequest:
    """ScanRequest wraps a Host and a port to scan."""

    host: Host
    port: int

    def __post_init__(self) -> None:
        assert 0 < self.port < 65536, "Port must be a number between 1 and 65535"


@dataclass(kw_only=True, slots=True)
class ScanResult:
    """ScanResult is the result scanning a port."""

    host: Host
    result: Service


@dataclass(kw_only=True, slots=True)
class Scanner:
    """Scanner scans ports."""

    log: logging.Logger = field(default_factory=lambda: common.get_logger("scanner"))
    lock: RLock = field(default_factory=RLock)
    wcnt: int
    cmdQ: Queue[Message] = field(init=False)
    scanQ: Queue[ScanRequest] = field(init=False)
    resQ: Queue[ScanResult] = field(init=False)
    interval: float = 2.0
    _active: bool = False

    def __post_init__(self) -> None:
        assert self.wcnt > 0
        socket.setdefaulttimeout(conn_timeout)
        self.cmdQ = Queue(self.wcnt * 2)
        self.scanQ = Queue(self.wcnt)
        self.resQ = Queue(self.wcnt * 2)

    @property
    def active(self) -> bool:
        """Return the Scanner's active flag."""
        with self.lock:
            return self._active

    def _feeder(self) -> None:
        self.log.debug("Feeder thread is coming up...")
        db: Database = Database()
        try:
            while self.active:
                with self.lock:
                    cnt = self.wcnt
                hosts: list[Host] = db.host_get_random(cnt)
                for host in hosts:
                    req = self._select_port(db, host)
                    if req is not None:
                        self.scanQ.put(req)
                    else:
                        self.log.debug("No port was found for %s/%s",
                                       host.name,
                                       host.addr)
                time.sleep(self.interval)
        finally:
            db.close()
            self.log.debug("Feeder thread is quitting.")

    def _gatherer(self) -> None:
        """Gather scanned ports and store them in the database."""
        self.log.debug("Gatherer threads is starting up.")
        db: Final[Database] = Database()
        try:
            while self.active:
                pass
        finally:
            db.close()
            self.log.debug("Gatherer thread is quitting.")

    def _scan_worker(self, wid: int) -> None:
        self.log.debug("Scan worker %02d starting up.",
                       wid)
        while self.active:
            pass

    def _select_port(self, db: Database, host: Host) -> Optional[ScanRequest]:
        """Pick a port to scan for <host>."""
        services: list[Service] = db.service_get_by_host(host)
        ports: Final[frozenset[int]] = frozenset({x.port for x in services})

        match host.src:
            case HostSource.MX:
                for p in (25, 110, 143, 587):
                    if p not in ports:
                        return ScanRequest(host=host, port=p)
            case HostSource.NS:
                if 53 not in ports:
                    return ScanRequest(host=host, port=53)

        plist: Final[list[int]] = random.sample(interesting_ports, len(interesting_ports))

        for p in plist:
            if p not in ports:
                return ScanRequest(host=host, port=p)

        # We've exhausted all our options.
        # We COULD return a random number from the interval [1,65535], but for now,
        # we just bail.
        return None

    def scan_port(self, req: ScanRequest) -> Optional[ScanResult]:
        """Scan a port."""
        match req.port:
            case 21 | 22 | 25 | 110 | 143:
                reply = self.scan_tcp_generic(req.host.astr, req.port)
            case 80 | 443 | 8080:
                reply = self.scan_http(req.host.astr, req.port, req.host.name, req.port == 443)
            case _:
                raise ValueError(f"Don't know how to handle port {req.port}")

        if reply.status:
            svc: Final[Service] = Service(
                host_id=req.host.host_id,
                port=req.port,
                added=datetime.now(),
                response=reply.response,
            )
            return ScanResult(host=req.host, result=svc)
        return None

    def scan_tcp_generic(self, addr: str, port: int) -> ScanReply:
        """Open a TCP connection and report what is received."""
        if not 0 < port < 65536:
            raise ValueError(f"Invalid port {port}")
        try:
            conn = socket.create_connection((addr, port))
            response = conn.recv(rcv_buf)

            return ScanReply(True, str(response))
        except ConnectionError as cerr:
            cname: Final[str] = cerr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {cerr}"
            self.log.error(msg)
            return ScanReply(False, msg)
        finally:
            conn.close()

    def scan_http(self,
                  addr: str,
                  port: int,
                  hostname: Optional[str] = None,
                  ssl: bool = False) -> ScanReply:
        """Attempt to scan an HTTP server."""
        if not 0 < port < 65536:
            raise ValueError(f"Invalid port {port}")
        try:
            schema: Final[str] = "https" if ssl else "http"
            if hostname is not None:
                uri: str = f"{schema}://{hostname}:{port}/"
            else:
                uri = f"{schema}://{addr}:{port}/"

            response = requests.head(uri, timeout=conn_timeout)
            return ScanReply(True, response.headers["Server"])
        except ConnectionError as cerr:
            cname: str = cerr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {cerr}"
            self.log.error(msg)
            return ScanReply(False, msg)
        except requests.exceptions.RequestException as rerr:
            cname = rerr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {rerr}"
            self.log.error(msg)
            return ScanReply(False, msg)

    def scan_dns(self, addr: str, port: int) -> ScanReply:
        """Attempt to query a DNS server for its server string."""
        if not 0 < port < 65536:
            raise ValueError(f"Invalid port {port}")
        try:
            res = Resolver("", False)
            res.nameservers = [addr]

            ans = res.resolve("version.bind.", "TXT", "CH")

            if ans.rrset is not None:
                return ScanReply(True, ans.rrset[0].to_text())
            return ScanReply(False, "")
        except dns.exception.DNSException as derr:
            cname: Final[str] = derr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {derr}"
            self.log.error(msg)
            return ScanReply(False, msg)

    def scan_finger(self, addr: str, port: int) -> ScanReply:
        """Attempt to finger a finger server."""
        if not 0 < port < 65536:
            raise ValueError(f"Invalid port {port}")

        try:
            conn = socket.create_connection((addr, port))
            conn.send(b"root\r\n")

            response = conn.recv(rcv_buf)

            return ScanReply(True, response.decode())
        except ConnectionError as cerr:
            cname: Final[str] = cerr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {cerr}"
            self.log.error(msg)
            return ScanReply(False, msg)

    def scan_telnet(self, addr: str, port: int) -> ScanReply:
        """Attempt to scan a telnet server."""
        if not 0 < port < 65536:
            raise ValueError(f"Invalid port {port}")

        try:
            conn = Telnet(addr, port)
            data = conn.read_until(b"Sapperlot", conn_timeout)
            return ScanReply(True, data.decode())
        except ConnectionError as cerr:
            cname: Final[str] = cerr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {cerr}"
            self.log.error(msg)
            return ScanReply(False, msg)
        finally:
            conn.close()

# def scan_snmp(self, addr: str, port: int) -> ScanReply:
#     """Attempt to scan an SNMP server."""
#     mib: Final[str] = ".1.3.6.1.2.1.1.1.0"

# Local Variables: #
# python-indent: 4 #
# End: #
