#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-27 16:13:14 krylon>
#
# /data/code/python/pykuang/test_generator.py
# created on 10. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.test_generator

(c) 2025 Benjamin Walkenhorst
"""


import os
import shutil
import unittest
from datetime import datetime
from typing import Final, Optional

from pykuang import common
from pykuang.generator import HostGenerator
from pykuang.model import Host

test_dir: Final[str] = os.path.join(
    "/tmp",
    datetime.now().strftime(f"{common.AppName.lower()}_test_database_%Y%m%d_%H%M%S"))

host_cnt: Final[int] = 5

skip_gen: Final[bool] = True


class TestHostGenerator(unittest.TestCase):
    """Test the HostGenerator."""

    _gen: Optional[HostGenerator] = None

    @classmethod
    def gen(cls, g: Optional[HostGenerator] = None) -> HostGenerator:
        """Set or return the HostGenerator."""
        if g is not None:
            cls._gen = g
        if cls._gen is not None:
            return cls._gen

        raise ValueError("HostGenerator instance is None")

    @classmethod
    def setUpClass(cls) -> None:
        """Prepare the testing environment."""
        common.set_basedir(test_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up afterwards."""
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_01_create_generator(self) -> None:
        """Attempt to create a HostGenerator."""
        g: HostGenerator = HostGenerator()
        self.assertIsNotNone(g)
        self.assertIsInstance(g, HostGenerator)
        self.gen(g)

    def test_02_generate_hosts(self) -> None:
        """Attempt to generate some Hosts."""
        if skip_gen:
            self.skipTest("I'm not in the mood.")
        g: HostGenerator = self.gen()

        hosts: list[Host] = []

        for _ in range(host_cnt):
            h: Host = g.generate_host()
            self.assertIsNotNone(h)
            self.assertIsInstance(h, Host)
            hosts.append(h)


# Local Variables: #
# python-indent: 4 #
# End: #
