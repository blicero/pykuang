#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-26 17:42:03 krylon>
#
# /data/code/python/pykuang/scanner.py
# created on 26. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.scanner

(c) 2025 Benjamin Walkenhorst
"""


from typing import Final

interesting_port: Final[list[int]] = [
    21,
    22,
    23,
    25,
    53,
    79,
    80,
    110,
    143,
    161,
    220,
    389,
    443,
    1433,  # MSSQL
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    5900,
    8080,
]


# Local Variables: #
# python-indent: 4 #
# End: #
