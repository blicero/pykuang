#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-06 17:55:30 krylon>
#
# /data/code/python/pykuang/cache.py
# created on 05. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.cache

(c) 2025 Benjamin Walkenhorst
"""

# import logging
# import pickle
# from dataclasses import dataclass
# from datetime import datetime, timedelta
# from enum import Enum, auto
# from typing import Any, Optional

# import lmdb

from pykuang.common import KuangError


class CacheError(KuangError):
    """Exception class to indicate errors in the caching layer"""


class TxError(CacheError):
    """TxError indicates an error related to transaction-handling."""


# Local Variables: #
# python-indent: 4 #
# End: #
