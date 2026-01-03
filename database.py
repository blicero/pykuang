#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2026-01-03 15:54:39 krylon>
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
from pykuang.model import XFR, Host, HostSource, Service


class DBError(KuangError):
    """Base class for database-related exceptions."""


qinit: Final[list[str]] = [
    """
CREATE TABLE host (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    addr TEXT UNIQUE NOT NULL,
    src INTEGER NOT NULL,
    added INTEGER NOT NULL,
    last_contact INTEGER,
    sysname TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    xfr INTEGER NOT NULL DEFAULT 0,
    CHECK (src BETWEEN 1 AND 5)
) STRICT
    """,
    "CREATE INDEX host_added_idx ON host (added)",
    "CREATE INDEX host_last_contact_idx ON host (COALESCE(last_contact, 0))",
    "CREATE INDEX host_xfr_idx ON host (xfr = 0)",
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
    UNIQUE (host_id, port),
    CHECK (port BETWEEN 1 AND 65535)
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
CREATE TABLE xfr (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    added INTEGER NOT NULL,
    started INTEGER NOT NULL DEFAULT 0,
    finished INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 0,
    CHECK (finished >= started)
) STRICT
    """,
    "CREATE INDEX xfr_start_idx ON xfr (started)",
    "CREATE INDEX xfr_finish_idx ON xfr (finished)",
    "CREATE INDEX xfr_name_idx ON xfr (name)",
]


class Query(Enum):
    """Query identifies a particular operation on the database."""

    HostAdd = auto()
    HostGetByAddr = auto()
    HostGetByID = auto()
    HostGetRandom = auto()
    HostGetNoXFR = auto()
    HostGetAll = auto()
    HostUpdateLastContact = auto()
    HostUpdateSysname = auto()
    HostUpdateLocation = auto()
    HostSetXfr = auto()

    SvcAdd = auto()
    SvcGetByPort = auto()
    SvcGetByHost = auto()

    XfrAdd = auto()
    XfrStart = auto()
    XfrEnd = auto()
    XfrGetUnfinished = auto()
    XfrGetByID = auto()
    XfrGetByName = auto()


qdb: Final[dict[Query, str]] = {
    Query.HostAdd: "INSERT INTO host (name, addr, src, added) VALUES (?, ?, ?, ?) RETURNING id",
    Query.HostGetByAddr: """
SELECT
    id,
    name,
    src,
    added,
    last_contact,
    sysname,
    location,
    xfr
FROM host
WHERE addr = ?
    """,
    Query.HostGetByID: """
SELECT
    addr,
    src,
    name,
    added,
    last_contact,
    sysname,
    location,
    xfr
FROM host
WHERE id = ?
    """,
    Query.HostGetRandom: """
SELECT
    id,
    addr,
    name,
    src,
    added,
    last_contact,
    sysname,
    location,
    xfr
FROM host
ORDER BY COALESCE(last_contact, 0) DESC
LIMIT ?
OFFSET ABS(RANDOM()) % MAX((SELECT COUNT(*) FROM host), 1)
    """,
    Query.HostGetNoXFR: """
SELECT
    id,
    addr,
    src,
    name,
    added,
    last_contact,
    sysname,
    location,
FROM host
WHERE xfr = 0
ORDER BY added
LIMIT ?
    """,
    Query.HostGetAll: """
SELECT
    id,
    addr,
    src,
    name,
    added,
    last_contact,
    sysname,
    location,
    xfr
FROM host
""",
    Query.HostUpdateLastContact: "UPDATE host SET last_contact = ? WHERE id = ?",
    Query.HostUpdateSysname: "UPDATE host SET sysname = ? WHERE id = ?",
    Query.HostUpdateLocation: "UPDATE host SET location = ? WHERE id = ?",
    Query.HostSetXfr: "UPDATE host SET xfr = 1 WHERE id = ?",
    Query.SvcAdd: """
INSERT INTO svc (host_id, port, added, response)
         VALUES (      ?,    ?,     ?,        ?)
RETURNING id
""",
    Query.SvcGetByHost: """
SELECT
    id,
    port,
    added,
    response
FROM svc
WHERE host_id = ?
ORDER BY port
    """,
    Query.XfrAdd: "INSERT INTO xfr (name, added) VALUES (?, ?) RETURNING id",
    Query.XfrStart: "UPDATE xfr SET started = ? WHERE id = ?",
    Query.XfrEnd: "UPDATE xfr SET finished = ?, status = ? WHERE id = ?",
    Query.XfrGetUnfinished: """
SELECT
    id,
    name,
    added,
    started,
    status
FROM xfr
WHERE finished = 0
LIMIT ?
    """,
    Query.XfrGetByName: """
SELECT
    id,
    added,
    started,
    finished,
    status
FROM xfr
WHERE name = ?
    """,
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
                                         host.src.value,
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
                          src=HostSource(row[2]),
                          added=datetime.fromtimestamp(row[3]),
                          last_contact=maybe_timestamp(row[4]),
                          sysname=row[5],
                          location=row[6],
                          xfr=(row[7] != 0),
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
            src=HostSource(row[1]),
            name=row[2],
            added=datetime.fromtimestamp(row[3]),
            last_contact=maybe_timestamp(row[4]),
            sysname=row[5],
            location=row[6],
            xfr=(row[7] != 0),
        )

        return host

    def host_get_random(self, cnt: int) -> list[Host]:
        """Get up to <cnt> Hosts picked randomly from the database."""
        assert cnt > 0, "Host count must be positive."
        cur = self.db.cursor()
        cur.execute(qdb[Query.HostGetRandom], (cnt, ))

        hosts: list[Host] = []

        for row in cur:
            host: Host = Host(
                host_id=row[0],
                addr=ip_address(row[1]),
                name=row[2],
                src=HostSource(row[3]),
                added=datetime.fromtimestamp(row[4]),
                last_contact=maybe_timestamp(row[5]),
                sysname=row[6],
                location=row[7],
                xfr=(row[8] != 0),
            )

            hosts.append(host)

        return hosts

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
                src=HostSource(row[2]),
                name=row[3],
                added=datetime.fromtimestamp(row[4]),
                last_contact=maybe_timestamp(row[5]),
                sysname=row[6],
                location=row[7],
                xfr=(row[8] != 0),
            )

            hosts.append(host)

        return hosts

    def host_get_no_xfr(self, cnt: int) -> list[Host]:
        """Get <cnt> Hosts for the XFRProcessor."""
        cur = self.db.cursor()
        cur.execute(qdb[Query.HostGetNoXFR], (cnt, ))
        hosts: list[Host] = []

        for row in cur:
            host = Host(
                host_id=row[0],
                addr=ip_address(row[1]),
                src=HostSource(row[2]),
                name=row[3],
                added=datetime.fromtimestamp(row[4]),
                last_contact=maybe_timestamp(row[5]),
                sysname=row[6],
                location=row[7],
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

    def host_set_xfr(self, host: Host) -> None:
        """Set a Host's XFR flag."""
        cur = self.db.cursor()
        cur.execute(qdb[Query.HostSetXfr], (host.host_id, ))
        host.xfr = True

    def service_add(self, svc: Service) -> None:
        """Add a scanned port to the database."""
        try:
            cur: Final[sqlite3.Cursor] = self.db.cursor()
            cur.execute(qdb[Query.SvcAdd],
                        (svc.host_id, svc.port, int(svc.added.timestamp()), svc.response))

            row = cur.fetchone()
            if row is None:
                self.log.error("Adding service %d:%d did not return an ID.",
                               svc.host_id,
                               svc.port)
            else:
                svc.sv_id = row[0]
        except sqlite3.Error as err:
            cname: Final[str] = err.__class__.__name__
            msg = f"{cname} trying to add Service {svc.host_id}:{svc.port}: {err}"
            self.log.error(msg)
            raise DBError(msg) from err

    def service_get_by_host(self, host: Host) -> list[Service]:
        """Get all scanned ports for <host>."""
        cur: Final[sqlite3.Cursor] = self.db.cursor()
        cur.execute(qdb[Query.SvcGetByHost], (host.host_id, ))

        ports: list[Service] = []

        for row in cur:
            svc: Service = Service(
                sv_id=row[0],
                host_id=host.host_id,
                port=row[1],
                added=datetime.fromtimestamp(row[2]),
                response=row[3],
            )
            ports.append(svc)

        return ports

    def xfr_add(self, xfr: XFR) -> None:
        """Add a DNS zone to the database to be XFR'ed."""
        cur: sqlite3.Cursor = self.db.cursor()
        cur.execute(qdb[Query.XfrAdd], (xfr.name, int(xfr.added.timestamp())))
        row = cur.fetchone()
        if row is None:
            msg = \
                f"Error adding XFR zone {xfr.name}: No exception, but no ID was returned, either."""
            self.log.error(msg)
            raise DBError(msg)
        xfr.zone_id = row[0]

    def xfr_start(self, xfr: XFR) -> None:
        """Mark an XFR as started."""
        now = datetime.now()
        cur: sqlite3.Cursor = self.db.cursor()
        cur.execute(qdb[Query.XfrStart], (int(now.timestamp()), xfr.zone_id))
        xfr.started = now

    def xfr_finish(self, xfr: XFR, status: bool) -> None:
        """Mark an XFR as finished."""
        now = datetime.now()
        cur = self.db.cursor()
        cur.execute(qdb[Query.XfrEnd], (int(now.timestamp()), status, xfr.zone_id))
        xfr.finished = now
        xfr.status = status

    def xfr_get_unfinished(self, limit: int = -1) -> list[XFR]:
        """Get up to <limit> unfinished XFRs from the database.

        If <limit> is < 0, return all unfinished XFRs.
        """
        cur = self.db.cursor()
        cur.execute(qdb[Query.XfrGetUnfinished], (limit, ))
        xfrs: list[XFR] = []

        for row in cur:
            x: XFR = XFR(
                zone_id=row[0],
                name=row[1],
                added=datetime.fromtimestamp(row[2]),
                started=datetime.fromtimestamp(row[3]),
                status=row[4],
            )
            xfrs.append(x)

        return xfrs

    def xfr_get_by_name(self, name: str) -> Optional[XFR]:
        """Look up an XFR by the zone name."""
        cur = self.db.cursor()
        cur.execute(qdb[Query.XfrGetByName], (name, ))
        row = cur.fetchone()
        if row is None:
            return None

        x: XFR = XFR(
            zone_id=row[0],
            name=name,
            added=datetime.fromtimestamp(row[1]),
            started=datetime.fromtimestamp(row[2]),
            finished=datetime.fromtimestamp(row[3]),
            status=bool(row[4]),
        )
        return x


def maybe_timestamp(ts: Optional[int]) -> Optional[datetime]:
    """Return a datetime object if <ts> is not None, else None."""
    if ts is not None:
        return datetime.fromtimestamp(ts)
    return None

# Local Variables: #
# python-indent: 4 #
# End: #
