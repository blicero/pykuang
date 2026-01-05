#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time-stamp: <2026-01-05 15:40:56 krylon>
#
# /data/code/python/pykuang/main.py
# created on 05. 01. 2026
# (c) 2026 Benjamin Walkenhorst
#
# This file is part of the PyKuang network scanner. It is distributed under the
# terms of the GNU General Public License 3. See the file LICENSE for details
# or find a copy online at https://www.gnu.org/licenses/gpl-3.0

"""
pykuang.main

(c) 2026 Benjamin Walkenhorst
"""


import argparse
import pathlib
import time

from pykuang import common
from pykuang.nexus import Nexus


def main() -> None:
    argp: argparse.ArgumentParser = argparse.ArgumentParser()
    argp.add_argument("-g", "--generator",
                      type=int,
                      default=4,
                      help="The number of Generator threads to run in parallel")
    argp.add_argument("-s", "--scanner",
                      type=int,
                      default=4,
                      help="The number of Scanner threads to run in parallel")
    argp.add_argument("-x", "--xfr",
                      type=int,
                      default=2,
                      help="The number of XFR threads to run in parallel")
    argp.add_argument("-b", "--basedir",
                      type=pathlib.Path,
                      default=common.path.base(),
                      help="Directory to store application data in")

    args = argp.parse_args()
    common.set_basedir(args.basedir)

    nx = Nexus(gcnt=args.generator,
               xcnt=args.xfr,
               scnt=args.scanner)

    try:
        nx.start()
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("Telling Nexus to stop.")
        nx.stop()


if __name__ == '__main__':
    main()

# Local Variables: #
# python-indent: 4 #
# End: #
