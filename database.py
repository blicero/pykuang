#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-12-08 16:28:07 krylon>
#
# /data/code/python/pykuang/database.py
# created on 05. 12. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.database

(c) 2025 Benjamin Walkenhorst
"""

import sqlite3
from datetime import datetime
from enum import Enum, auto
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from threading import Lock
from typing import Final, Optional, Union

import krylib

from pykuang import common
from pykuang.common import KuangError
from pykuang.model import Host


class DBError(KuangError):
    """Base class for database-related exceptions."""


qinit: Final[list[str]] = [
    """
CREATE TABLE host (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    addr TEXT UNIQUE NOT NULL,
    added INTEGER NOT NULL,
    last_contact INTEGER,
    sysname TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT ''
) STRICT
    """,
    "CREATE INDEX host_added_idx ON host (added)",
    "CREATE INDEX host_last_contact_idx ON host (last_contact)",
    """
CREATE TABLE svc (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    added INTEGER NOT NULL,
    response TEXT,
    FOREIGN KEY (host_id) REFERENCES host (id)
        ON UPDATE RESTRICT
        ON DELETE CASCADE,
    UNIQUE (host_id, port)
) STRICT
    """,
    "CREATE INDEX svc_host_idx ON svc (host_id)",
    "CREATE INDEX svc_port_idx ON svc (port)",
    "CREATE INDEX svc_added_idx ON svc (added)",
    """
CREATE TRIGGER tr_host_contact
AFTER INSERT ON svc
BEGIN
    UPDATE host
    SET last_contact = unixepoch()
    WHERE id = NEW.host_id;
END
    """,
    """
CREATE TABLE zone (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    started INTEGER NOT NULL,
    finished INTEGER,
    status INTEGER NOT NULL DEFAULT 0
) STRICT
    """,
    "CREATE INDEX zone_finish_idx ON zone (finished)",
]


class Query(Enum):
    """Query identifies a particular operation on the database."""

    HostAdd = auto()
    HostGetByAddr = auto()
    HostGetByID = auto()
    HostGetAll = auto()
    HostUpdateLastContact = auto()
    HostUpdateSysname = auto()
    HostUpdateLocation = auto()

    SvcAdd = auto()
    SvcGetByPort = auto()
    SvcGetByHost = auto()


qdb: Final[dict[Query, str]] = {
    Query.HostAdd: "INSERT INTO host (name, addr, added) VALUES (?, ?, ?) RETURNING id",
    Query.HostGetByAddr: """
SELECT
    id,
    name,
    added,
    last_contact,
    sysname,
    location
FROM host
WHERE addr = ?
    """,
    Query.HostGetByID: """
SELECT
    addr,
    name,
    added,
    last_contact,
    sysname,
    location
FROM host
WHERE id = ?
    """,
    Query.HostGetAll: """
SELECT
    id,
    addr,
    name,
    added,
    last_contact,
    sysname,
    location
FROM host
""",
    Query.HostUpdateLastContact: "UPDATE host SET last_contact = ? WHERE id = ?",
}


open_lock: Final[Lock] = Lock()


class Database:
    """Database... you can probably guess."""

    __slots__ = [
        "db",
        "log",
        "path",
    ]

    def __init__(self, path: Optional[Union[Path, str]] = None) -> None:
        if path is None:
            self.path = common.path.db
        else:
            match path:
                case x if isinstance(x, Path):
                    self.path = x
                case x if isinstance(x, str):
                    self.path = Path(x)

        self.log = common.get_logger("database")
        self.log.debug("Open database at %s", self.path)

        with open_lock:
            exist: Final[bool] = krylib.fexist(str(self.path))
            self.db = sqlite3.connect(str(self.path))
            self.db.isolation_level = None

            cur: Final[sqlite3.Cursor] = self.db.cursor()
            cur.execute("PRAGMA foreign_keys = true")
            cur.execute("PRAGMA journal_mode = WAL")

            if not exist:
                self.__create_db()

    def __create_db(self) -> None:
        """Initialize a freshly created database"""
        self.log.debug("Initialize fresh database at %s", self.path)
        with self.db:
            for query in qinit:
                try:
                    cur: sqlite3.Cursor = self.db.cursor()
                    cur.execute(query)
                except sqlite3.OperationalError as operr:
                    self.log.debug("%s executing init query: %s\n%s\n",
                                   operr.__class__.__name__,
                                   operr,
                                   query)
                    raise
        self.log.debug("Database initialized successfully.")

    def close(self) -> None:
        """Close the database connection."""
        self.db.close()
        # self.db = None
        del self.db

    def __enter__(self) -> None:
        self.db.__enter__()

    def __exit__(self, ex_type, ex_val, tb):
        return self.db.__exit__(ex_type, ex_val, tb)

    def host_add(self, host: Host) -> None:
        """Add a Host to the Database."""
        now: Final[datetime] = datetime.now()
        cur: Final[sqlite3.Cursor] = self.db.cursor()
        cur.execute(qdb[Query.HostAdd], (host.name,
                                         str(host.addr),
                                         int(now.timestamp())))
        row = cur.fetchone()
        if row is None:
            msg = f"Adding Host {host.addr}/{host.name} did not return an ID"
            self.log.error(msg)
            raise DBError(msg)
        host.host_id = row[0]
        host.added = now

    def host_get_by_addr(self, addr: Union[str, IPv4Address, IPv6Address]) -> Optional[Host]:
        """Lookup a Host by its address."""
        astr: Final[str] = addr if isinstance(addr, str) else str(addr)
        cur: Final[sqlite3.Cursor] = self.db.cursor()
        cur.execute(qdb[Query.HostGetByAddr], (astr, ))
        row = cur.fetchone()

        if row is None:
            return None

        if isinstance(addr, str):
            addr = ip_address(addr)

        host: Host = Host(host_id=row[0],
                          name=row[1],
                          addr=addr,
                          added=datetime.fromtimestamp(row[2]),
                          last_contact=maybe_timestamp(row[3]),
                          sysname=row[4],
                          location=row[5],
                          )

        return host

    def host_get_by_id(self, host_id: int) -> Optional[Host]:
        """Lookup a Host by its database ID."""
        cur = self.db.cursor()
        cur.execute(qdb[Query.HostGetByID], (host_id, ))
        row = cur.fetchone()

        if row is None:
            return None

        host: Host = Host(
            host_id=host_id,
            addr=ip_address(row[0]),
            name=row[1],
            added=datetime.fromtimestamp(row[2]),
            last_contact=maybe_timestamp(row[3]),
            sysname=row[4],
            location=row[5],
        )

        return host

    def host_get_all(self) -> list[Host]:
        """Get all hosts from the database.

        Use with caution, this may return A LOT of Hosts.
        """
        cur = self.db.cursor()
        cur.execute(qdb[Query.HostGetAll])

        hosts: list[Host] = []

        for row in cur:
            host: Host = Host(
                host_id=row[0],
                addr=ip_address(row[1]),
                name=row[2],
                added=datetime.fromtimestamp(row[3]),
                last_contact=maybe_timestamp(row[4]),
                sysname=row[5],
                location=row[6],
            )

            hosts.append(host)

        return hosts

    def host_update_contact(self, host: Host, tstamp: Optional[datetime] = None) -> None:
        """Update a Hosts last_contact stamp.

        If no timestamp is given, use the current time.
        """
        if host.host_id < 1:
            msg = "Host has no ID"
            self.log.error(msg)
            raise ValueError(msg)
        if tstamp is None:
            tstamp = datetime.now()

        cur = self.db.cursor()
        cur.execute(qdb[Query.HostUpdateLastContact], (tstamp, host.host_id))
        host.last_contact = tstamp


def maybe_timestamp(ts: Optional[int]) -> Optional[datetime]:
    """Return a datetime object if <ts> is not None, else None."""
    if ts is not None:
        return datetime.fromtimestamp(ts)
    return None

# Local Variables: #
# python-indent: 4 #
# End: #
