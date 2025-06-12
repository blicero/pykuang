#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-12 17:52:54 krylon>
#
# /data/code/python/pykuang/database.py
# created on 07. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.database

(c) 2025 Benjamin Walkenhorst
"""

import logging
import sqlite3
from datetime import datetime
from enum import IntEnum, auto, unique
from threading import Lock
from typing import Final, Optional

import krylib

from pykuang import common
from pykuang.model import Host, Xfr, XfrStatus


class DBError(common.KuangError):
    """DBError indicates an error in the database."""


class IntegrityError(DBError):
    """IntegrityError indicates a violation of a database constraint."""


open_lock: Final[Lock] = Lock()

qinit: Final[list[str]] = [
    """
CREATE TABLE host (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    addr TEXT UNIQUE NOT NULL,
    src INTEGER NOT NULL,
    atime INTEGER NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT ''
) STRICT
""",
    "CREATE INDEX host_name_idx ON host (name)",
    "CREATE INDEX host_addr_idx ON host (addr)",
    "CREATE INDEX host_src_idx ON host (src)",
    "CREATE INDEX host_atime_idx ON host (atime)",
    """
CREATE TABLE port (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL,
    port_no INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    response TEXT,
    UNIQUE(host_id, port_no),
    CHECK (port_no BETWEEN 1 AND 65536),
    FOREIGN KEY (host_id) REFERENCES host (id)
      ON UPDATE RESTRICT
      ON DELETE CASCADE
) STRICT
    """,
    "CREATE INDEX port_host_idx ON port (host_id)",
    "CREATE INDEX port_port_idx ON port (port_no)",
    "CREATE INDEX port_time_idx ON port (timestamp)",
    """
CREATE TABLE xfr (
    id INTEGER PRIMARY KEY,
    zone TEXT UNIQUE NOT NULL,
    begin INTEGER NOT NULL,
    end INTEGER,
    status INTEGER NOT NULL,
    CHECK ((end IS NULL) OR (end > begin))
) STRICT
    """,
    "CREATE UNIQUE INDEX xfr_zone_idx ON xfr (zone)",
    "CREATE INDEX xfr_begin_idx ON xfr (begin)",
    "CREATE INDEX xfr_end_idx ON xfr (end)",
]


@unique
class qid(IntEnum):
    """qid is a symbolic constant to identify database queries."""

    HostAdd = auto()
    HostSetLocation = auto()
    HostSetOS = auto()
    HostGetByName = auto()
    HostGetByAddr = auto()
    HostGetRandom = auto()
    HostGetAll = auto()
    PortAdd = auto()
    PortGetByHost = auto()
    PortGetByPort = auto()
    PortGetRecent = auto()
    XfrAdd = auto()
    XfrEnd = auto()
    XfrGetByZone = auto()
    XfrGetAll = auto()
    XfrGetUnfinished = auto()


qdb: Final[dict[qid, str]] = {
    qid.HostAdd: "INSERT INTO host (name, addr, src, atime) VALUES (?, ?, ?, ?)",
    qid.HostSetLocation: "UPDATE host SET location = ? WHERE id = ?",
    qid.HostSetOS: "UPDATE host SET os = ? WHERE id = ?",
    qid.HostGetByName: """
SELECT
    id,
    addr,
    src,
    atime,
    location,
    os
FROM host WHERE name = ?
    """,
    qid.HostGetByAddr: """
SELECT
    id,
    name,
    src,
    atime,
    location,
    os
FROM host
WHERE addr = ?
    """,
    qid.HostGetAll: """
SELECT
    id,
    name,
    addr,
    src,
    atime,
    location,
    os
FROM host
    """,
    qid.XfrAdd: "INSERT INTO xfr (zone, begin, status) VALUES (?, ?)",
    qid.XfrEnd: "UPDATE xfr SET end = ?, status = ? WHERE id = ?",
    qid.XfrGetByZone: """
SELECT
    id,
    begin,
    end,
    status
FROM xfr
WHERE zone = ?
    """,
    qid.XfrGetAll: """
SELECT
    id,
    zone,
    begin,
    end,
    status
FROM xfr
    """,
    qid.XfrGetUnfinished: """
SELECT
    id,
    zone,
    begin
FROM xfr
WHERE end IS NULL
    """,
}


class Database:
    """Database provides persistence and operations to search and modify said data."""

    __slots__ = [
        "db",
        "log",
        "path",
    ]

    db: sqlite3.Connection
    log: logging.Logger
    path: str

    def __init__(self, path: str = "") -> None:
        if path == "":
            self.path = common.path.db()
        else:
            self.path = path
        self.log = common.get_logger("database")
        self.log.debug("Open database at %s", self.path)

        with open_lock:
            exist: bool = krylib.fexist(self.path)
            self.db = sqlite3.connect(self.path,
                                      check_same_thread=False)

            cur: sqlite3.Cursor = self.db.cursor()
            cur.execute("PRAGMA foreign_keys = true")
            cur.execute("PRAGMA journal_mode = WAL")

            if not exist:
                self.__create_db()

    def __create_db(self) -> None:
        with self.db:
            for q in qinit:
                self.log.debug("Execute SQL: %s",
                               q)
                cur: sqlite3.Cursor = self.db.cursor()
                cur.execute(q)

    def __enter__(self) -> None:
        self.db.__enter__()

    def __exit__(self, ex_type, ex_val, traceback):
        return self.db.__exit__(ex_type, ex_val, traceback)

    def close(self) -> None:
        """Close the underlying database connection explicitly."""
        self.db.close()

    def host_add(self, h: Host) -> None:
        """Add a Host to the database."""
        now = datetime.now()
        cur = self.db.cursor()
        cur.execute(qdb[qid.HostAdd], (h.name, str(h.addr), h.src.value, int(now.timestamp())))
        assert cur.lastrowid is not None
        h.host_id = cur.lastrowid
        h.add_stamp = now

    def host_set_location(self, h: Host, loc: str) -> None:
        """Set a Host's location."""
        cur = self.db.cursor()
        cur.execute(qdb[qid.HostSetLocation], (loc, h.host_id))
        h.location = loc

    def host_set_os(self, h: Host, os: str) -> None:
        """Set a Host's OS."""
        cur = self.db.cursor()
        cur.execute(qdb[qid.HostSetOS], (os, h.host_id))
        h.os = os

    def xfr_add(self, zone: str) -> Optional[Xfr]:
        """Register a DNS zone to be transferred in the database."""
        now = datetime.now()
        cur = self.db.cursor()
        try:
            cur.execute(qdb[qid.XfrAdd], (zone, int(now.timestamp()), XfrStatus.Blank))
        except sqlite3.Error as err:
            msg = f"Failed to add XFR of {zone}: {err}"
            self.log.error(msg)
            raise DBError(msg) from err
        assert cur.lastrowid is not None
        xfr = Xfr(xid=cur.lastrowid, zone=zone, begin=now, status=XfrStatus.Blank)
        return xfr

    def xfr_end(self, xfr: Xfr, status: XfrStatus) -> None:
        """Mark an attempted zone transfer as finished (successfully or not)."""
        now = datetime.now()
        cur = self.db.cursor()
        cur.execute(qdb[qid.XfrEnd], (int(now.timestamp()), status, xfr.xid))
        xfr.end = now
        xfr.status = status

# Local Variables: #
# python-indent: 4 #
# End: #
