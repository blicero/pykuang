#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-09 21:46:15 krylon>
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
from ipaddress import IPv4Address
from typing import NamedTuple, Optional

from pykuang.blacklist import IPBlacklist, reserved_networks


class SampleAddr(NamedTuple):
    """Bla"""

    addr: IPv4Address
    expect_match: bool
    expect_err: bool


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
            SampleAddr(IPv4Address("10.10.42.215"), True, False),
        ]

        for s in samples:
            m = self.bl().match(s.addr)
            self.assertEqual(m, s.expect_match)


# Local Variables: #
# python-indent: 4 #
# End: #
