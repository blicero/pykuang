#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-10 17:41:50 krylon>
#
# /data/code/python/pykuang/test_blacklist.py
# created on 09. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.test_blacklist

(c) 2025 Benjamin Walkenhorst
"""

import unittest
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Final, NamedTuple, Optional, Union

from pykuang.blacklist import (IPBlacklist, NameBlacklist, name_patterns,
                               reserved_networks)


class SampleAddr(NamedTuple):
    """Bla"""

    addr: Union[IPv4Address, IPv6Address]
    expect_match: bool
    expect_err: bool


class SampleName(NamedTuple):
    """Bla"""

    name: str
    expect_match: bool


class IPBlacklistTest(unittest.TestCase):
    """Test the IPBlacklist."""

    _bl: IPBlacklist

    @classmethod
    def bl(cls, bl: Optional[IPBlacklist] = None) -> IPBlacklist:
        """Set or return the Blacklist."""
        if bl is not None:
            cls._bl = bl
        return cls._bl

    def test_01_create_blacklist(self) -> None:
        """Test creating a Blacklist."""
        try:
            bl = IPBlacklist(reserved_networks)
        except Exception as err:  # pylint: disable-msg=W0718
            self.fail(f"Failed to create IPBlacklist: {err}")
        else:
            self.bl(bl)

    def test_02_match_addr(self) -> None:
        """Test matching various IP addresses."""
        samples: list[SampleAddr] = [
            SampleAddr(ip_address("10.10.42.215"), True, False),
            SampleAddr(ip_address("42.23.1.9"), False, False),
            SampleAddr(ip_address("51.195.118.34"), False, False),
            SampleAddr(ip_address("::1"), True, False),
            SampleAddr(ip_address("fd00::bc80:5e52:e29c:ccda"), True, False),
            SampleAddr(ip_address("2a00:4841:1640:6d00:b772:9efc:6e0c:fec3"), False, False),
        ]

        for s in samples:
            m = self.bl().match(s.addr)
            self.assertEqual(m, s.expect_match)


class NameBlacklistTest(unittest.TestCase):
    """Test the NameBlacklist."""

    _bl: NameBlacklist

    @classmethod
    def bl(cls, bl: Optional[NameBlacklist] = None) -> NameBlacklist:
        """Get or set the TestCase's blacklist."""
        if bl is not None:
            cls._bl = bl
        return cls._bl

    def test_01_create_blacklist(self) -> None:
        """Test creating a Blacklist."""
        try:
            bl = NameBlacklist(name_patterns)
        except Exception as err:  # pylint: disable-msg=W0718
            self.fail(f"Failed to create NameBlacklist: {err}")
        else:
            self.bl(bl)

    def test_02_match(self) -> None:
        """Test matching hostnames against the Blacklist."""
        samples: Final[list[SampleName]] = [
            SampleName("en.wikipedia.org", False),
            SampleName("dhcp21.example.com", True),
            SampleName("noname.ibm.com", True),
        ]

        bl = self.bl()

        for s in samples:
            self.assertEqual(bl.match(s.name), s.expect_match)

# Local Variables: #
# python-indent: 4 #
# End: #
