#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-08 16:23:16 krylon>
#
# /data/code/python/pykuang/test_database.py
# created on 08. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.test_database

(c) 2025 Benjamin Walkenhorst
"""

import os
import shutil
import unittest
from datetime import datetime
from ipaddress import ip_address
from typing import Final, Optional

from pykuang import common
from pykuang.database import Database
from pykuang.model import Host

test_dir: Final[str] = os.path.join(
    "/tmp",
    datetime.now().strftime(f"{common.AppName.lower()}_test_database_%Y%m%d_%H%M%S"))
host_count: Final[int] = 25


class TestDatabase(unittest.TestCase):
    """Test the database."""

    conn: Optional[Database] = None

    @classmethod
    def setUpClass(cls) -> None:
        """Prepare the testing environment."""
        common.set_basedir(test_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up afterwards."""
        shutil.rmtree(test_dir, ignore_errors=True)

    @classmethod
    def db(cls, db: Optional[Database] = None) -> Database:
        """Set or return the database."""
        if db is not None:
            cls.conn = db
            return db
        if cls.conn is not None:
            return cls.conn

        raise ValueError("No Database connection exists")

    def test_01_db_open(self) -> None:
        """Attempt to open a fresh Database."""
        db: Database = Database()
        self.assertIsNotNone(db)
        self.assertIsInstance(db, Database)  # ???
        self.db(db)

    def test_02_host_add(self) -> None:
        """Attempt adding a couple of Hosts to the Database."""
        db: Database = self.db()

        with db:
            for i in range(host_count):
                addr = ip_address(f"172.16.32.{i+1}")
                name = f"host{i+1:02d}.example.com"

                host: Host = Host(
                    addr=addr,
                    name=name,
                    added=datetime.now(),
                )

                db.host_add(host)
                self.assertGreater(host.host_id, 0)

    def test_03_host_get_all(self) -> None:
        """Attempt to load all Hosts."""
        db: Database = self.db()

        hosts: list[Host] = db.host_get_all()

        self.assertIsNotNone(hosts)
        self.assertIsInstance(hosts, list)
        self.assertEqual(len(hosts), host_count)

        for host in hosts:
            self.assertIsInstance(host, Host)


# Local Variables: #
# python-indent: 4 #
# End: #
