#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-14 17:13:39 krylon>
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
from queue import Queue
from random import randbytes, random
from threading import local, Lock, Thread
from typing import Final, Optional, Union

from dns import rdatatype
from dns.exception import DNSException
from dns.resolver import Resolver

from pykuang import common
from pykuang.blacklist import (IPBlacklist, NameBlacklist, name_patterns,
                               reserved_networks)
from pykuang.config import Config
from pykuang.model import Host, HostSource


class Generator:  # pylint: disable-msg=R0903
    """Generator cranks out random IP adresses, basically."""

    __slots__ = [
        "log",
        "loc",
        "cache_path",
        "name_blacklist",
        "net_blacklist",
        "v6_weight",
        "res",
        "queue",
        "worker_cnt",
        "active_flag",
        "lock",
    ]

    log: logging.Logger
    loc: local
    cache_path: str
    name_blacklist: NameBlacklist
    net_blacklist: IPBlacklist
    v6_weight: float
    res: Resolver
    queue: Queue
    worker_cnt: int
    active_flag: bool
    lock: Lock

    def __init__(self, cache_path: str = "", v6: float = 0.03125) -> None:
        cfg = Config()

        if cache_path == "":
            self.cache_path = common.path.ipcache()
        else:
            self.cache_path = cache_path

        # self.cache = dbm.open(cache_path, 'c', 0o644)

        self.loc = local()
        self.log = common.get_logger("generator")
        self.name_blacklist = NameBlacklist(name_patterns)
        self.net_blacklist = IPBlacklist(reserved_networks)
        self.v6_weight = v6
        self.res = Resolver("", False)
        self.res.nameservers = cfg.get("Generator", "Resolver")
        self.res.edns = True
        self.queue = Queue()
        self.worker_cnt = cfg.get("Generator", "Parallel")
        self.active_flag = False
        self.lock = Lock()

    def _get_cache(self):
        with self.lock:
            try:
                return self.loc.cache
            except AttributeError:
                self.loc.cache = dbm.open(self.cache_path, 'c', 0o644)
                return self.loc.cache

    def is_active(self) -> bool:
        """Return the state of the Generator's active flag."""
        with self.lock:
            return self.active_flag

    def stop(self) -> None:
        """Clear the Generator's active flag."""
        with self.lock:
            self.active_flag = False

    def start(self, cnt: int = -1) -> None:
        """Start the Generator."""
        if cnt == -1:
            cnt = self.worker_cnt
        with self.lock:
            self.active_flag = True
        for i in range(cnt):
            wname = f"Generator#{i+1}"
            w = Thread(target=self._worker, name=wname, args=(wname, ), daemon=True)
            w.start()

    def _worker(self, name: str) -> None:
        self.log.debug("Worker %s starting up.", name)
        try:
            while self.is_active():
                h: Optional[Host] = self.gen_host()
                if h is not None:
                    self.queue.put(h)
        finally:
            self.log.debug("Worker %s is done.", name)

    def gen_ip(self) -> Union[IPv4Address, IPv6Address]:
        """Generate a random IP address."""
        cnt: int = 4
        if random() < self.v6_weight:
            # self.log.debug("Generate IPv6 address.")
            cnt = 16

        cache = self._get_cache()

        addr: Union[IPv4Address, IPv6Address] = ip_address(randbytes(cnt))

        while (str(addr) in cache) or self.net_blacklist.match(addr):
            addr = ip_address(randbytes(cnt))

        cache[str(addr)] = "True"
        return addr

    def resolve_name(self, addr: Union[IPv4Address, IPv6Address]) -> Optional[str]:
        """Attempt to resolve an IP address into a hostname."""
        query: Final[str] = addr.reverse_pointer
        try:
            ans = self.res.resolve(query, rdatatype.PTR)
        except DNSException:
            return None

        if ans.rrset is None or len(ans.rrset) == 0:
            return None

        name: str = ans.rrset[0].to_text()
        if name.endswith("."):
            name = name[:-1]
        return name

    def gen_host(self) -> Optional[Host]:
        """Attempt to generate a Host."""
        addr = self.gen_ip()
        name: Optional[str] = self.resolve_name(addr)

        while name is None or self.name_blacklist.match(name):
            addr = self.gen_ip()
            name = self.resolve_name(addr)

        h: Host = Host(name=name, addr=addr, src=HostSource.Generator)
        return h


# Local Variables: #
# python-indent: 4 #
# End: #
