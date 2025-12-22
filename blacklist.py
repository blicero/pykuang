#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-22 18:02:16 krylon>
#
# /data/code/python/pykuang/blacklist.py
# created on 08. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.blacklist

(c) 2025 Benjamin Walkenhorst
"""


import logging
import re
from dataclasses import dataclass, field
from ipaddress import (IPv4Address, IPv4Network, IPv6Address, IPv6Network,
                       ip_address, ip_network)
from threading import Lock
from typing import Final, Sequence, Union

from pykuang import common

forbidden_networks: Final[list[str]] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.0.0.0/8",
]

forbidden_names: Final[list[str]] = [
    "\\bdiu?p-?\\d*\\.",
    "(?:versanet|telekom|uni-paderborn|upb)\\.(?:de|net|com|biz|eu)\\.?$",
    "[.]?nothing[.]",
    "[.]example[.](?:org|net|com)[.]?$",
    "[avs]?dsl",
    "\\.in-addr\\.",
    "\\.invalid\\.?",
    "\\b(?:wireless|wlan|wimax|wan|vpn|vlan)",
    "\\b\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}\\b",
    "\\bincorrect(?:ly)?\\b",
    "\\bnot.configured\\b",
    "\\bpools?\\b",
    "\\bunn?ass?igned\\b",
    "^(?:client|host)(?:-?\\d+)?",
    "^(?:un|not-)(?:known|ass?igned|alloc(?:ated)?|registered|provisioned|used|defined|delegated)",
    "^[.]$",
    "^[*]",
    "^\\w*eth(?:ernet)[^.]*\\.",
    "^\\w\\d+\\[\\-.]",
    "^customer-",
    "^customer\\.",
    "^dyn\\d+",
    "^generic-?host",
    "^h\\d+s\\d+",
    "^host\\d+\\.",
    "^illegal",
    "^internal-host",
    "^ip(?:-?\\d+|addr)",
    "^mobile",
    "^no(?:-reverse)?-dns",
    "^(?:no-?)?reverse",
    "^no.ptr",
    "^softbank\\d+\\.bbtec",
    "^this.ip",
    "^user-?\\d+\\.",
    "aol\\.com\\.?$",
    "cable",
    "dhcp",
    "dial-?(?:in|up)?",
    "dyn(?:amic)?[-.0-9]",
    "dyn(?:amic)ip",
    "early.registration",
    "(?:edu)?roam",
    "localhost",
    "myvzw\\.com",
    "no-dns(?:-yet)?",
    "non-routed",
    "ppp",
    "rr\\.com\\.?$",
    "umts",
    "wanadoo\\.[a-z]{2,3}\\.?$",
    "^\\w*[.]$",
    "reverse-not-set",
    "uu[.]net[.]?$",
    "(?:ne|ad)[.]jp[.]?$",
    "[.](?:cn|mil)[.]?$",
    "^noname[.]",
]


@dataclass(kw_only=True, slots=True)
class NameBlacklistItem:
    """NameBlacklistItem is a pattern to match hostnames."""

    pat: re.Pattern
    hit_cnt: int = 0

    def is_match(self, name: str) -> bool:
        """Return True if the item matches the given name."""
        if self.pat.search(name) is not None:  # pylint: disable-msg=E1101
            self.hit_cnt += 1
            return True

        return False


@dataclass(kw_only=True, slots=True)
class NameBlacklist:
    """A list of patterns to match hostnames."""

    patterns: list[NameBlacklistItem] = field(default_factory=list)
    lock: Lock = field(default_factory=Lock)
    log: logging.Logger = field(default_factory=lambda: common.get_logger("bl_name"))
    dbg: bool = True

    @classmethod
    def from_list(cls, names: Sequence[Union[str, re.Pattern]]) -> 'NameBlacklist':
        """Create a NameBlacklist from a list of patterns."""
        patterns: list[NameBlacklistItem] = []

        for n in names:
            match n:
                case re.Pattern() as x:
                    patterns.append(NameBlacklistItem(pat=x))
                case str() as x:
                    pat = re.compile(x, re.I)
                    patterns.append(NameBlacklistItem(pat=pat))

        bl = NameBlacklist(patterns=patterns)
        return bl

    @classmethod
    def default(cls) -> 'NameBlacklist':
        """Return a NameBlacklist of the default patterns."""
        return cls.from_list(forbidden_names)

    def is_match(self, name: str) -> bool:
        """Return True if an item in the Blacklist matches the given name."""
        with self.lock:
            for pat in self.patterns:
                if pat.is_match(name):
                    if self.dbg:
                        self.log.debug("Hostname %s is matched by pattern %s",
                                       name,
                                       pat.pat.pattern)
                    self.patterns.sort(key=lambda x: x.hit_cnt, reverse=True)
                    return True
        return False


@dataclass(kw_only=True, slots=True)
class IPBlacklistItem:
    """IPBlacklistItem represents a range of IP addresses that are blacklisted."""

    net: Union[IPv4Network, IPv6Network]
    hit_cnt: int = 0

    def is_match(self, addr: Union[IPv4Address, IPv6Address]) -> bool:
        """Return True if the <addr> is in the Item's network."""
        if addr in self.net:
            self.hit_cnt += 1
            return True
        return False


@dataclass(kw_only=True, slots=True)
class IPBlacklist:
    """IPBlacklist is a list of IP address ranges that are blacklisted."""

    networks: list[IPBlacklistItem]
    lock: Lock = field(default_factory=Lock)
    log: logging.Logger = field(default_factory=lambda: common.get_logger("bl_addr"))
    dbg: bool = True

    @classmethod
    def from_list(cls, lst: Sequence[Union[IPv4Network, IPv6Network, str]]) -> 'IPBlacklist':
        """Create an IPBlacklist from list of IP address ranges."""
        ranges: list[IPBlacklistItem] = []
        for r in lst:
            if isinstance(r, (IPv4Network, IPv6Network)):
                ranges.append(IPBlacklistItem(net=r))
            else:
                ranges.append(IPBlacklistItem(net=ip_network(r)))
        return IPBlacklist(networks=ranges)

    @classmethod
    def default(cls) -> 'IPBlacklist':
        """Return an IPBlacklist of the default networks."""
        return cls.from_list(forbidden_networks)

    def is_match(self, addr: Union[str, IPv4Address, IPv6Address]) -> bool:
        """Return True if <addr> is in any of the blacklisted address ranges."""
        with self.lock:
            if isinstance(addr, str):
                try:
                    addr = ip_address(addr)
                except ValueError as verr:
                    self.log.error("'%s' does not look like an IP address: %s.",
                                   addr,
                                   verr)
            for net in self.networks:
                if net.is_match(addr):
                    self.networks.sort(key=lambda x: x.hit_cnt, reverse=True)
                    return True
        return False

# Local Variables: #
# python-indent: 4 #
# End: #
