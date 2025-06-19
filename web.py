#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-19 16:18:39 krylon>
#
# /data/code/python/pykuang/web.py
# created on 18. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.web

(c) 2025 Benjamin Walkenhorst
"""

import json
import logging
import os
import re
import socket
from datetime import datetime
from threading import Lock
from typing import Any, Final

import bottle
from bottle import response, route
from jinja2 import Environment, FileSystemLoader

from pykuang import common, config
from pykuang.database import Database

mime_types: Final[dict[str, str]] = {
    ".css":  "text/css",
    ".map":  "application/json",
    ".js":   "text/javascript",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif":  "image/gif",
    ".json": "application/json",
    ".html": "text/html",
}

suffix_pat: Final[re.Pattern] = re.compile("([.][^.]+)$")


def find_mime_type(path: str) -> str:
    """Attempt to determine the MIME type for a file."""
    m = suffix_pat.search(path)
    if m is None:
        return "application/octet-stream"
    suffix = m[1]
    if suffix in mime_types:
        return mime_types[suffix]
    return "application/octet-stream"


class WebUI:
    """WebUI provides a web interface to inspect the database and control the subsystems."""

    __slots__ = [
        "log",
        "root",
        "lock",
        "env",
        "addr",
        "port",
    ]

    log: logging.Logger
    root: str
    lock: Lock
    env: Environment
    addr: str
    port: int

    def __init__(self, root: str = "") -> None:
        self.log = common.get_logger("web")
        self.lock = Lock()

        cfg = config.Config()
        self.addr = cfg.get("Web", "Addr")
        self.port = cfg.get("Web", "Port")

        if root == "":
            self.root = os.path.join(".", "assets")
        else:
            self.root = root

        self.env = Environment(loader=FileSystemLoader(os.path.join(self.root, "templates")))
        self.env.globals = {
            "dbg": common.DEBUG,
            "app_string": f"{common.APP_NAME} {common.APP_VERSION}",
            "hostname": socket.gethostname(),
        }

        bottle.debug(common.DEBUG)
        route("/main", callback=self.main)
        route("/ajax/beacon", callback=self.handle_beacon)
        route("/static/<path>", callback=self.staticfile)
        route("/favicon.ico", callback=self.handle_favicon)

    def _tmpl_vars(self) -> dict:
        """Return a dict with a few default variables filled in already."""
        default: dict = {
            "now": datetime.now().strftime(common.TIME_FMT),
            "year": datetime.now().year,
            "time_fmt": common.TIME_FMT,
        }

        return default

    def run(self) -> None:
        """Run the web server."""
        bottle.run(host=self.addr, port=self.port, debug=common.DEBUG)

    def main(self) -> str:
        """Presents the landing page."""
        try:
            db: Database = Database()
            response.set_header("Cache-Control", "no-store, max-age=0")
            tmpl = self.env.get_template("main.jinja")
            tmpl_vars = self._tmpl_vars()
            tmpl_vars["title"] = f"{common.APP_NAME} {common.APP_VERSION} - Main"
            tmpl_vars["year"] = datetime.now().year
            tmpl_vars["host_cnt"] = db.host_cnt()
            tmpl_vars["xfr_cnt"] = db.xfr_cnt()
            tmpl_vars["port_cnt"] = db.port_cnt()
            # tmpl_vars["hosts"] = db.host_get_all()
            return tmpl.render(tmpl_vars)
        finally:
            db.close()

    # Static files

    def handle_favicon(self) -> bytes:
        """Handle the request for the favicon."""
        path: Final[str] = os.path.join(self.root, "static", "favicon.ico")
        with open(path, "rb") as fh:
            response.set_header("Content-Type", "image/vnd.microsoft.icon")
            response.set_header("Cache-Control",
                                "no-store, max-age=0" if common.DEBUG else "max-age=7200")
            return fh.read()

    def staticfile(self, path) -> bytes:
        """Return one of the static files."""
        # TODO Determine MIME type?
        #      Set caching header?
        mtype = find_mime_type(path)
        response.set_header("Content-Type", mtype)
        response.set_header("Cache-Control",
                            "no-store, max-age=0" if common.DEBUG else "max-age=7200")

        full_path = os.path.join(self.root, "static", path)
        if not os.path.isfile(full_path):
            self.log.error("Static file %s was not found", path)
            response.status = 404
            return b''
        with open(full_path, "rb") as fh:
            return fh.read()

    # AJAX Handlers

    def handle_beacon(self) -> str:
        """Handle the AJAX call for the beacon."""
        jdata: dict[str, Any] = {
            "Status": True,
            "Message": common.APP_NAME,
            "Timestamp": datetime.now().strftime(common.TIME_FMT),
            "Hostname": socket.gethostname(),
        }

        response.set_header("Content-Type", "application/json")
        response.set_header("Cache-Control", "no-store, max-age=0")

        return json.dumps(jdata)


# Local Variables: #
# python-indent: 4 #
# End: #
