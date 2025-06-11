#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-11 20:07:43 krylon>
#
# /data/code/python/pykuang/config.py
# created on 11. 06. 2025
# (c) 2025 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.config

(c) 2025 Benjamin Walkenhorst
"""

import logging
from threading import Lock
from typing import Any, Final

import krylib
import tomlkit
from tomlkit.items import Table
from tomlkit.toml_document import Container, TOMLDocument
from tomlkit.toml_file import TOMLFile

from pykuang import common

default_config: Final[str] = """# Time-stamp: <>

[Global]

[Generator]
Resolver = ["10.10.0.1"]
Parallel = 16

"""

open_lock: Final[Lock] = Lock()


class Config:
    """Config handles the parsing and writing of the confguration file."""

    __slots__ = [
        "log",
        "doc",
        "cfg",
        "path",
    ]

    log: logging.Logger
    doc: TOMLDocument
    cfg: TOMLFile
    path: str

    def __init__(self, path: str = "") -> None:
        if path == "":
            self.path = common.path.config()
        else:
            self.path = path

        common.init_app()

        with open_lock:
            exist: Final[bool] = krylib.fexist(self.path)
            if not exist:
                with open(self.path, "w", encoding="utf-8") as fh:
                    fh.write(default_config)

        self.cfg = TOMLFile(self.path)
        self.doc = self.cfg.read()

        self.log = common.get_logger("Config")

    def get(self, section: str, key: str) -> Any:
        """Get a config value."""
        try:
            assert section in self.doc
            s = self.doc[section]
            # self.log.debug("Section %s is a %s",
            #                section,
            #                s.__class__.__name__)
            assert isinstance(s, Table)
            return s[key]
        except tomlkit.exceptions.TOMLKitError as err:
            self.log.error('%s while trying to retrieve "%s.%s": %s\n\n%s\n\n',
                           err.__class__.__name__,
                           section,
                           key,
                           err,
                           krylib.fmt_err(err))
            raise

    def update(self, section: str, key: str, val: Any) -> None:
        """Set a config value."""
        try:
            assert section in self.doc
            sec = self.doc[section]
            assert isinstance(sec, Container)
            sec[key] = val

            with open_lock:
                self.cfg.write(self.doc)
        except tomlkit.exceptions.TOMLKitError as err:
            self.log.error('%s while trying to update config "%s.%s" -> %s: %s\n\n%s\n\n',
                           err.__class__.__name__,
                           section,
                           key,
                           val,
                           err,
                           krylib.fmt_err(err))
            raise


# Local Variables: #
# python-indent: 4 #
# End: #
