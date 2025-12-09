#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-09 15:35:41 krylon>
#
# /data/code/python/pykuang/test_blacklist.py
# created on 09. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.test_blacklist

(c) 2025 Benjamin Walkenhorst
"""

import os
import re
import unittest
from datetime import datetime
from typing import Final, Optional

from pykuang import common
from pykuang.blacklist import NameBlacklist, NameBlacklistItem

test_dir: Final[str] = os.path.join(
    "/tmp",
    datetime.now().strftime(f"{common.AppName.lower()}_test_blacklist_%Y%m%d_%H%M%S"))


class TestNameBlacklist(unittest.TestCase):
    """Test the hostname Blacklist."""

    _bl: NameBlacklist

    @classmethod
    def bl(cls, bl: Optional[NameBlacklist] = None) -> NameBlacklist:
        """Set or return the NameBlacklist."""
        if bl is not None:
            cls._bl = bl

        if cls._bl is not None:
            return cls._bl

        raise ValueError("NameBlacklist instance is None.")

    def test_01_create_blacklist(self) -> None:
        """Test creating the NameBlacklist."""
        patterns: Final[list[str]] = [
            "\\.in-addr\\.",
            "\\.invalid\\.?",
            "\\b(?:wireless|wlan|wimax|wan|vpn|vlan)",
            "\\b\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}\\b",
        ]

        items: list[NameBlacklistItem] = [NameBlacklistItem(pat=re.compile(x, re.I))
                                          for x in patterns]

        self.bl(NameBlacklist(patterns=items))

    def test_02_match(self) -> None:
        """Test matching hostnames against the NameBlacklist."""
        test_cases: Final[list[tuple[str, bool]]] = [
            ("www01.funny-domain.com", False),
            ("smtp.invalid.example.com", True),
            ("mail.your-mom.com", False),
            ("dyn01.wireless.dad-jokes.com", True),
        ]

        bl = self.bl()

        for c in test_cases:
            m: bool = bl.is_match(c[0])
            self.assertEqual(m, c[1])

# Local Variables: #
# python-indent: 4 #
# End: #
