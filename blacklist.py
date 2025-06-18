#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-17 20:33:13 krylon>
#
# /data/code/python/pykuang/blacklist.py
# created on 08. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.blacklist

(c) 2025 Benjamin Walkenhorst
"""

import re
from abc import ABC, abstractmethod
from ipaddress import (IPv4Address, IPv4Network, IPv6Address, IPv6Network,
                       ip_address, ip_network)
from threading import Lock
from typing import Final, Sequence, Union

reserved_networks: Final[list[str]] = [
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

name_patterns: Final[list[str]] = [
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
    "t-ipconnect",
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
    "^\\d+$",
    "versanet",
    "^user-?\\d+\\.",
    "aol\\.com\\.?$",
    "cable",
    "dhcp",
    "dial-?(?:in|up)?",
    "dyn(?:amic)?[-.0-9]",
    "dyn(?:amic)?ip",
    "early.registration",
    "(?:edu)?roam",
    "localhost",
    "myvzw\\.com",
    "no-dns(?:-yet)?",
    "no-data",
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


class BlacklistPattern(ABC):
    """A BlacklistPattern consists of a pattern and a counter."""

    cnt: int = 0

    @abstractmethod
    def match(self, item) -> bool:
        """Match the given item against the Pattern."""


class NetworkPattern(BlacklistPattern):
    """NetworkPattern is an IP Address or an IP network."""

    net: Union[IPv4Network, IPv6Network]

    def __init__(self, net: Union[str, IPv4Network, IPv6Network]) -> None:
        self.cnt = 0
        if isinstance(net, str):
            self.net = ip_network(net)
        elif isinstance(net, (IPv4Network, IPv6Network)):
            self.net = net
        else:
            raise TypeError(
                f"Invalid type for net ({net.__class__.__name__}), expected str or IPv4Network"
            )

    def match(self, item: Union[IPv4Address, IPv6Address]) -> bool:
        """Match the given IP address against the Pattern's network."""
        if item in self.net:
            self.cnt += 1
            return True
        return False


class NamePattern(BlacklistPattern):
    """NamePattern is a regular expression to match hostnames."""

    pat: re.Pattern

    def __init__(self, pat: Union[str, re.Pattern]) -> None:
        self.cnt = 0
        if isinstance(pat, str):
            self.pat = re.compile(pat, re.I)
        else:
            self.pat = pat

    def match(self, item: str) -> bool:
        """Return True if the given string is matched by the instance's pattern."""
        if self.pat.match(item):
            self.cnt += 1
            return True
        return False


class Blacklist(ABC):
    """Base class for blacklists."""

    lock: Lock
    items: Sequence[BlacklistPattern]

    @abstractmethod
    def _sort(self) -> None:
        pass

    @abstractmethod
    def match(self, s) -> bool:
        """Return True if the given string s is matched by the Blacklist."""


class IPBlacklist(Blacklist):
    """IPBlacklist matches network addresses against a list of networks."""

    items: list[NetworkPattern]

    def __init__(self, items: list[str]) -> None:
        self.lock = Lock()
        self.items = [NetworkPattern(x) for x in items]

    def _sort(self) -> None:
        self.items.sort(reverse=True, key=lambda x: x.cnt)

    def match(self, s: Union[str, IPv4Address, IPv6Address]) -> bool:
        """Return True if the given address is matched by the Blacklist."""
        if isinstance(s, str):
            s = ip_address(s)

        if s.is_multicast or \
           s.is_private or \
           s.is_reserved or \
           s.is_loopback or \
           s.is_link_local:
            return True

        with self.lock:
            for net in self.items:
                if net.match(s):
                    self._sort()
                    return True
        return False


class NameBlacklist(Blacklist):
    """NameBlacklist matches hostnames against a list of regular expressions."""

    items: list[NamePattern]

    def __init__(self, items: list[str]) -> None:
        self.lock = Lock()
        self.items = [NamePattern(x) for x in items]

    def _sort(self) -> None:
        self.items.sort(reverse=True, key=lambda x: x.cnt)

    def match(self, s: str) -> bool:
        """Return True if the given string is matched by any elements in the Blacklist."""
        with self.lock:
            for pat in self.items:
                if pat.match(s):
                    self._sort()
                    return True
        return False

# Local Variables: #
# python-indent: 4 #
# End: #
