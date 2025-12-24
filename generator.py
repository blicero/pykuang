#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-24 15:17:42 krylon>
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
import time
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address
from queue import Empty, Queue, ShutDown
from random import randint
from threading import RLock, Thread
from typing import Final, Optional, Union

from dns.exception import Timeout
from dns.rcode import Rcode
from dns.resolver import (NXDOMAIN, Answer, LifetimeTimeout, NoAnswer,
                          NoNameservers, Resolver)

from pykuang import common
from pykuang.blacklist import IPBlacklist, NameBlacklist
from pykuang.cache import Cache, CacheDB, CacheType
from pykuang.control import Cmd, Message
from pykuang.database import Database
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

        self.res.timeout = 2.5
        self.res.lifetime = 2.5

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
        except NoAnswer:
            pass
        except Timeout:
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


q_timeout: Final[int] = 5


@dataclass(kw_only=True, slots=True)
class ParallelGenerator:
    """Generate Hosts in multiple threads to increase throughput."""

    wcnt: int
    log: logging.Logger = field(default_factory=lambda: common.get_logger("pgen"))
    lock: RLock = field(default_factory=RLock)
    _active: bool = False
    cmdQ: Queue[Message] = field(init=False)
    hostQ: Queue[Host] = field(init=False)
    _id_cnt: int = 0

    def __post_init__(self) -> None:
        assert self.wcnt > 0
        self.cmdQ = Queue(self.wcnt)
        self.hostQ = Queue(0)

    @property
    def active(self) -> bool:
        """Return the ParallelGenerator's active flag."""
        with self.lock:
            return self._active

    def start(self) -> None:
        """Start the worker threads."""
        with self.lock:
            self._active = True

            hw: Thread = Thread(target=self._host_worker, name="host_worker", daemon=False)
            hw.start()

            for _ in range(self.wcnt):
                self._id_cnt += 1
                wid: int = self._id_cnt
                gw: Thread = Thread(target=self._gen_worker,
                                    name=f"gen_worker_{wid:02d}",
                                    args=(wid, ),
                                    daemon=False)
                gw.start()

    def stop(self) -> None:
        """If active, stop all running worker threads."""
        if not self.active:
            return

        with self.lock:
            self._active = False
            cnt: Final[int] = self.wcnt

        for _ in range(cnt):
            message = Message(Tag=Cmd.Stop)
            self.cmdQ.put(message)

    def start_one(self) -> None:
        """If active, start one more worker thread."""
        if not self.active:
            self.log.error("ParallelGenerator is not active.")
            return

        with self.lock:
            self._id_cnt += 1
            wid: int = self._id_cnt
            gw: Thread = Thread(target=self._gen_worker,
                                name=f"gen_worker_{wid:02d}",
                                args=(wid, ),
                                daemon=False)
            gw.start()
            self.wcnt += 1

    def stop_one(self) -> None:
        """If active, stop one worker Thread."""
        if not self.active:
            self.log.error("ParallelGenerator is not active.")
            return

        with self.lock:
            msg: Message = Message(Tag=Cmd.Stop)
            self.cmdQ.put(msg)
            if self.wcnt == 1:
                self._active = False

    def _gen_worker(self, wid: int) -> None:
        """Generate Hosts. Lots of Hosts."""
        self.log.info("gen_worker #%02d reporting for work.", wid)
        gen: HostGenerator = HostGenerator()

        try:
            while self.active:
                try:
                    message: Message = self.cmdQ.get(False)
                except Empty:
                    pass
                else:
                    match message.Tag:
                        case Cmd.Stop:
                            self.log.info("gen_worker #%02d will quit now.", wid)
                            return
                        case Cmd.Pause:
                            self.log.info("gen_worker #%02d will pause for %d seconds.",
                                          wid,
                                          message.Payload)
                            time.sleep(message.Payload)

                try:
                    host: Host = gen.generate_host()
                    self.hostQ.put(host)
                except ShutDown:
                    self.log.info("gen_worker #%02d: HostQueue was shut down. I'm quitting.", wid)
                    return
        finally:
            self.log.info("gen_worker #%02d is finished. So long!", wid)
            with self.lock:
                self.wcnt -= 1

    def _host_worker(self) -> None:
        """Catch Hosts from the queue and add them to the database."""
        self.log.info("host_worker coming right up.")
        try:
            db: Database = Database()
            while self.active:
                try:
                    host: Host = self.hostQ.get(True, q_timeout)
                    with db:
                        db.host_add(host)
                except Empty:
                    pass
        finally:
            db.close()
            self.log.info("Host worker is quitting now.")
            self.hostQ.shutdown(True)

# Local Variables: #
# python-indent: 4 #
# End: #
