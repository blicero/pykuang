#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-18 18:26:04 krylon>
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

import logging
import os
import re
import socket
from datetime import datetime
from threading import Lock
from typing import Final

import bottle
from jinja2 import Environment, FileSystemLoader

from pykuang import common, config

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
        "tmpl_root",
        "lock",
        "env",
        "addr",
        "port",
    ]

    log: logging.Logger
    tmpl_root: str
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
            self.tmpl_root = os.path.join(".", "assets")
        else:
            self.tmpl_root = root

        self.env = Environment(loader=FileSystemLoader(os.path.join(self.root, "templates")))
        self.env.globals = {
            "dbg": common.DEBUG,
            "app_string": f"{common.APP_NAME} {common.APP_VERSION}",
            "hostname": socket.gethostname(),
        }

        bottle.debug(common.DEBUG)

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

# Local Variables: #
# python-indent: 4 #
# End: #
