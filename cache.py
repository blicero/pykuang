#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-09 18:09:54 krylon>
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

import logging
import os
import pickle
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from threading import RLock
from typing import Final, Optional, Union

import lmdb
from krylib import Singleton

from pykuang import common
from pykuang.common import KuangError


class CacheError(KuangError):
    """Exception class to indicate errors in the caching layer"""


class TxError(CacheError):
    """TxError indicates an error related to transaction-handling."""


class CacheType(Enum):
    """CacheType identifies the different types of cache we use."""

    IPCache = auto()


@dataclass(kw_only=True, slots=True)
class CacheItem:
    """CacheItem is a piece of data we want to cache, plus an expiration timestamp."""

    item: str
    expires: Optional[datetime] = None

    @property
    def valid(self) -> bool:
        """Return True if the Item's expiration time has not passed, yet."""
        return self.expires is None or self.expires > datetime.now()


@dataclass(kw_only=True, slots=True)
class Tx:
    """Tx wraps a database transaction."""

    log: logging.Logger
    tx: lmdb.Transaction
    rw: bool
    ttl: Optional[timedelta]

    def __getitem__(self, key: str) -> Optional[str]:
        val = self.tx.get(key.encode())
        if val is None:
            return None

        item = pickle.loads(val)
        if item.valid:
            return item.item
        if self.rw:
            self.tx.delete(key)

        return None

    def __setitem__(self, key: str, val: str) -> None:
        if not self.rw:
            raise TxError("Cannot change the database in a readonly transaction!")

        exp: Optional[datetime] = None
        if self.ttl is not None:
            exp = datetime.now() + self.ttl

        item = CacheItem(item=val, expires=exp)
        raw: Final[bytes] = pickle.dumps(item)

        self.tx.put(key.encode(), raw, overwrite=True)

    def __delitem__(self, key) -> None:
        if not self.rw:
            raise TxError("Cannot change the database in a readonly transaction!")

        self.tx.delete(key.encode())

    def __contains__(self, key) -> bool:
        val = self.tx.get(key.encode())
        if val is None:
            return False

        item = pickle.loads(val)
        if self.rw and not item.valid:
            self.tx.delete(key.encode())
        return item.valid


@dataclass(kw_only=True, slots=True)
class CacheDB:
    """CacheDB wraps a database with in the LMDB environment."""

    name: CacheType
    env: lmdb.Environment
    db: 'lmdb._Database' = field(default=None)
    log: logging.Logger = field(init=False)
    ttl: Optional[timedelta] = field(default_factory=lambda: timedelta(seconds=7200))

    def __post_init__(self) -> None:
        self.log = common.get_logger(f"cache.{self.name.name}")
        self.log.debug("%s cache coming right up.", self.name)
        if self.db is None:
            self.log.info("No database instance was provided, opening one now.")
            self.db = self.env.open_db(self.name.name)

    @contextmanager
    def tx(self, rw: bool = False):
        """Perform a database transaction. Unless rw is True, no changes are permitted."""
        tx: lmdb.Transaction = self.env.begin(write=rw, db=self.db)
        try:
            yield Tx(log=self.log, tx=tx, rw=rw, ttl=self.ttl)
        except Exception as err:  # noqa: F841 # pylint: disable-msg=W0718
            cname: Final[str] = err.__class__.__name__
            self.log.error("Abort transaction due to %s: %s\n%s",
                           cname,
                           err,
                           "\n".join(traceback.format_exception(err)))
            tx.abort()
        else:
            tx.commit()

    def purge(self, complete: bool = False) -> None:
        """Remove stale entries from the Cache. If <complete> is True, remove ALL entries."""
        self.log.debug("Purge %s cache", self.name)
        with self.env.begin(write=True, db=self.db) as tx:
            cur: lmdb.Cursor = tx.cursor()

            for key, val in cur:
                try:
                    item: CacheItem = pickle.loads(val)
                except pickle.PickleError as err:
                    self.log.error("PickleError trying to de-serialize cache item %s: %s",
                                   key,
                                   err)
                else:
                    self.log.debug("Check if Item %s has expired",
                                   item.item)
                    if complete or not item.valid:
                        cur.delete()


class Cache(metaclass=Singleton):
    """Cache provides the LMDB environment."""

    __slots__ = [
        "log",
        "lock",
        "env",
        "path",
    ]

    log: logging.Logger
    lock: RLock
    env: lmdb.Environment
    path: str

    def __init__(self, cache_root: str = "") -> None:
        """Initialize the cache environment."""
        map_size: Final[int] = 1 << (40 if os.uname().machine == 'x86_64' else 30)
        self.log = common.get_logger("cache")
        if cache_root == "":
            cache_root = str(common.path.cache.joinpath("lmdb"))
        self.path = cache_root
        self.log.debug("Open Cache environment in %s", cache_root)
        self.lock = RLock()
        self.env = lmdb.Environment(cache_root,
                                    subdir=True,
                                    map_size=map_size,
                                    metasync=False,
                                    create=True,
                                    max_dbs=8,
                                    )

    def get_db(self,
               name:
               CacheType, ttl: Optional[Union[int, float, timedelta]] = None) -> CacheDB:
        """Return the specified database."""
        # LMDB caches databases already, so we don't need to duplicate that.
        self.log.debug("Open %s cache.", name)
        ettl: Optional[timedelta] = None

        if isinstance(ttl, timedelta):
            ettl = ttl
        elif isinstance(ttl, (int, float)):
            ettl = timedelta(seconds=ttl)

        db: 'lmdb._Database' = self.env.open_db(name.name.encode())
        cdb = CacheDB(name=name, env=self.env, db=db, ttl=ettl)
        return cdb


# Local Variables: #
# python-indent: 4 #
# End: #
