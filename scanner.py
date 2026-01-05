#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2026-01-05 15:18:22 krylon>
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
from queue import Empty, Queue, ShutDown
from threading import RLock, Thread
from typing import Final, NamedTuple, Optional, Union

import dns
import requests
from dns.resolver import Resolver
from telnetlib3 import Telnet  # type: ignore # pylint: disable-msg=E0401

from pykuang import common
from pykuang.control import Cmd, Message
from pykuang.database import Database, DBError
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
    3270,  # Mainframe?
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    5900,
    8080,
    9023,  # possibly alternative port for telnet
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
    id_cnt: int = 1
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
    def wid(self) -> int:
        """Get a new, unique ID for a worker thread."""
        with self.lock:
            self.id_cnt += 1
            return self.id_cnt

    @property
    def active(self) -> bool:
        """Return the Scanner's active flag."""
        with self.lock:
            return self._active

    def start(self) -> None:
        """Start the worker threads."""
        self.log.debug("Scanner starting up...")
        with self.lock:
            self._active = True

        fthr = Thread(target=self._feeder, daemon=True, name="scanner.feeder")
        fthr.start()

        gthr = Thread(target=self._gatherer, daemon=True, name="scanner.gatherer")
        gthr.start()

        for _ in range(self.wcnt):
            wid = self.wid
            wthr = Thread(target=self._scan_worker,
                          args=(wid, ),
                          daemon=True,
                          name=f"scanner.scan_worker{wid:02d}")
            wthr.start()

    def stop(self) -> None:
        """Tell all the worker threads to quit."""
        self.log.debug("Telling Scanner to shutdown.")
        with self.lock:
            self._active = False

        self.scanQ.shutdown()
        self.resQ.shutdown()
        self.cmdQ.shutdown()

    def start_one(self) -> None:
        """Start another worker thread."""
        self.log.debug("Start another Scanner thread.")
        wid = self.wid
        wthr = Thread(target=self._scan_worker,
                      args=(wid, ),
                      daemon=True,
                      name=f"scanner.scan_worker{wid:02d}")
        wthr.start()

    def stop_one(self) -> None:
        """Stop one worker thread."""
        self.log.debug("Stopping one Scanner thread.")
        with self.lock:
            if self.wcnt < 1 or not self.active:
                self.log.error("Scanner does not appear to be active!")
                return
        msg = Message(Tag=Cmd.Stop)
        self.cmdQ.put(msg)

    def _feeder(self) -> None:
        self.log.debug("Feeder thread is coming up...")
        db: Database = Database()
        try:
            while self.active:
                with self.lock:
                    cnt = self.wcnt
                if cnt < 1:
                    time.sleep(self.interval)
                    continue
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
        except ShutDown:
            pass
        finally:
            db.close()
            self.log.debug("Feeder thread is quitting.")
            self.scanQ.shutdown()
            with self.lock:
                self._active = False

    def _scan_worker(self, wid: int) -> None:
        self.log.debug("Scan worker %02d starting up.",
                       wid)
        try:
            while self.active:
                try:
                    msg = self.cmdQ.get_nowait()
                except Empty:
                    pass
                else:
                    match msg.Tag:
                        case Cmd.StopOne | Cmd.Stop:
                            return
                try:
                    req: ScanRequest = self.scanQ.get(True, self.interval)
                    res: Optional[ScanResult] = self.scan_port(req)
                    if res is None:
                        pass
                except Empty:
                    time.sleep(self.interval)
                    continue
        except ShutDown:
            pass
        finally:
            self.log.info("Scan worker %02d is quitting.",
                          wid)
            with self.lock:
                self.wcnt -= 1

    def _gatherer(self) -> None:
        """Gather scanned ports and store them in the database."""
        self.log.debug("Gatherer threads is starting up.")
        db: Final[Database] = Database()
        try:
            while self.active:
                try:
                    res = self.resQ.get(True, self.interval)
                    svc: Service = res.result

                    with db:
                        db.service_add(svc)
                except Empty:
                    continue
                except DBError as err:
                    self.log.error("Failed to add Service to database: %s",
                                   err)
        except ShutDown:
            pass
        finally:
            with self.lock:
                self._active = False
            db.close()
            self.log.debug("Gatherer thread is quitting.")

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
        try:
            match req.port:
                case 21 | 22 | 25 | 110 | 143 | 220:
                    reply = self.scan_tcp_generic(req.host.astr, req.port)
                case 80 | 443 | 8080:
                    reply = self.scan_http(req.host.astr, req.port, req.host.name, req.port == 443)
                case 79:
                    reply = self.scan_finger(req.host.astr, req.port)
                case 23 | 3270 | 9023:
                    reply = self.scan_telnet(req.host.astr, req.port)
                case _:
                    #  self.log.debug("Don't know how to handle port %d", req.port)
                    return None

            if reply.status:
                svc: Final[Service] = Service(
                    host_id=req.host.host_id,
                    port=req.port,
                    added=datetime.now(),
                    response=reply.response,
                )
                return ScanResult(host=req.host, result=svc)
            return None
        except TimeoutError:
            return None

    def scan_tcp_generic(self, addr: str, port: int) -> ScanReply:
        """Open a TCP connection and report what is received."""
        if not 0 < port < 65536:
            raise ValueError(f"Invalid port {port}")
        try:
            conn = socket.create_connection((addr, port))
            response = conn.recv(rcv_buf)
            conn.close()

            return ScanReply(True, str(response))
        except ConnectionError as cerr:
            cname: Final[str] = cerr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {cerr}"
            self.log.error(msg)
            return ScanReply(False, msg)
        except TimeoutError as terr:
            cname: Final[str] = terr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {terr}"
            self.log.error(msg)
            return ScanReply(False, msg)

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

        conn: Optional[Telnet] = None

        try:
            conn = Telnet(addr, port)
            data = conn.read_until(b"Sapperlot", conn_timeout)
            return ScanReply(True, data.decode())
        except ConnectionError as cerr:
            cname: Final[str] = cerr.__class__.__name__
            msg = f"{cname} trying to connect to {addr}:{port}: {cerr}"
            self.log.error(msg)
            return ScanReply(False, msg)
        except TimeoutError:
            return ScanReply(False, "Timeout")
        finally:
            if conn is not None:
                conn.close()

# def scan_snmp(self, addr: str, port: int) -> ScanReply:
#     """Attempt to scan an SNMP server."""
#     mib: Final[str] = ".1.3.6.1.2.1.1.1.0"

# Local Variables: #
# python-indent: 4 #
# End: #
