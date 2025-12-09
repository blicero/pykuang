#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-08 18:33:42 krylon>
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


import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from threading import Lock
from typing import Union


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

    patterns: list[NameBlacklistItem]
    lock: Lock = field(default_factory=Lock)

    def is_match(self, name: str) -> bool:
        """Return True if an item in the Blacklist matches the given name."""
        with self.lock:
            for pat in self.patterns:
                if pat.is_match(name):
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

    def is_match(self, addr: Union[IPv4Address, IPv6Address]) -> bool:
        """Return True if <addr> is in any of the blacklisted address ranges."""
        with self.lock:
            for net in self.networks:
                if net.is_match(addr):
                    self.networks.sort(key=lambda x: x.hit_cnt, reverse=True)
                    return True
        return False

# Local Variables: #
# python-indent: 4 #
# End: #
