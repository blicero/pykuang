#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2025-06-07 15:13:12 krylon>
#
# /data/code/python/medusa/common.py
# created on 24. 01. 2024
# (c) 2024 Benjamin Walkenhorst
#
# This file is part of the Vox audiobook reader. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
medusa.common

(c) 2024 Benjamin Walkenhorst
"""

import logging
import logging.handlers
import os
from typing import Final
from threading import Lock

APP_NAME: Final[str] = "PyKuang"
APP_VERSION: Final[str] = "0.0.1"
DEBUG: Final[bool] = True
TIME_FMT: Final[str] = "%Y-%m-%d %H:%M:%S"
PORT: Final[int] = 7030


class KuangError(Exception):
    """Base class for error handling inside the application."""


class Path:
    """Holds the paths of folders and files used by the application"""

    __base: str

    def __init__(self, root: str = os.path.expanduser(f"~/.{APP_NAME.lower()}.d")) -> None:  # noqa
        self.__base = root

    def base(self, folder: str = "") -> str:
        """
        Return the base directory for application specific files.

        If path is a non-empty string, set the base directory to its value.
        """
        if folder != "":
            self.__base = folder
        return self.__base

    def window(self) -> str:
        """Return the path of the window state file"""
        return os.path.join(self.__base, f"{APP_NAME.lower()}.win")

    def db(self) -> str:  # pylint: disable-msg=C0103
        """Return the path to the database"""
        return os.path.join(self.__base, f"{APP_NAME.lower()}.db")

    def log(self) -> str:
        """Return the path to the log file"""
        return os.path.join(self.__base, f"{APP_NAME.lower()}.log")

    def spool(self) -> str:
        """Return the path of the spool directory."""
        return os.path.join(self.__base, "spool")

    def ipcache(self) -> str:
        """Return the path of the cache of IP addresses for the generator."""
        return os.path.join(self.__base, "ipcache.db")

    def config(self) -> str:
        """Return the path of the configuration file"""
        return os.path.join(self.__base, f"{APP_NAME.lower()}.toml")


path: Path = Path(os.path.expanduser(f"~/.{APP_NAME.lower()}.d"))

_lock: Final[Lock] = Lock()  # pylint: disable-msg=C0103
_cache: Final[dict[str, logging.Logger]] = {}  # pylint: disable-msg=C0103


def set_basedir(folder: str) -> None:
    """Set the base dir to the speficied path."""
    path.base(folder)
    init_app()


def init_app() -> None:
    """Initialize the application environment"""
    if not os.path.isdir(path.base()):
        print(f"Create base directory {path.base()}")
        os.mkdir(path.base())
    if not os.path.isdir(path.spool()):
        os.mkdir(path.spool())


def get_logger(name: str, terminal: bool = True) -> logging.Logger:
    """Create and return a logger with the given name"""
    with _lock:
        init_app()

        if name in _cache:
            return _cache[name]

        log_format = "%(asctime)s (%(name)-16s / line %(lineno)-4d) " + \
            "- %(levelname)-8s %(message)s"
        max_log_size = 256 * 2**20
        max_log_count = 4

        log_obj = logging.getLogger(name)
        log_obj.setLevel(logging.DEBUG)
        log_file_handler = logging.handlers.RotatingFileHandler(path.log(),
                                                                'a',
                                                                max_log_size,
                                                                max_log_count)

        log_fmt = logging.Formatter(log_format)
        log_file_handler.setFormatter(log_fmt)
        log_obj.addHandler(log_file_handler)

        if terminal:
            log_console_handler = logging.StreamHandler()
            log_console_handler.setFormatter(log_fmt)
            log_console_handler.setLevel(logging.DEBUG)
            log_obj.addHandler(log_console_handler)

        _cache[name] = log_obj
        return log_obj


# Local Variables: #
# python-indent: 4 #
# End: #
