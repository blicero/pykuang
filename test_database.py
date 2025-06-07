#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-07 16:24:55 krylon>
#
# /data/code/python/pykuang/test_database.py
# created on 07. 06. 2025
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
import unittest
from datetime import datetime
from typing import Final, Optional

from pykuang import common
from pykuang.database import Database

test_dir: Final[str] = os.path.join(
    datetime.now().strftime("pykuang_test_database_%Y%m%d_%H%M%S"))


class DBTest(unittest.TestCase):
    """Test the database."""

    conn: Optional[Database] = None

    @classmethod
    def setUpClass(cls) -> None:
        """Prepare the stuff."""
        common.set_basedir(test_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up the mess."""
        os.system(f'rm -rf "{test_dir}"')

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
        """Open the database."""
        db: Database = Database(common.path.db())
        self.assertIsNotNone(db)
        DBTest.db(db)

# Local Variables: #
# python-indent: 4 #
# End: #
