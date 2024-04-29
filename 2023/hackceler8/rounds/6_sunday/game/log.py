# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from enum import Enum
from logging.handlers import WatchedFileHandler

import argparse
import datetime
import logging
import os
import sys


def get_argument_parser():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--logfile', help="Logfile")
    parser.add_argument('--logfile-loglevel', default='info',
                        help="Minimal loglevel that is logged to the logfile")
    parser.add_argument('--loglevel', default='info',
                        help="Minimal loglevel that is logged to the console")
    return parser


# ANSI color codes
class AnsiColor(Enum):
    BLACK = 30
    RED = 31
    GREEN = 32
    BROWN = 33
    BLUE = 34
    PURPLE = 35
    CYAN = 36
    LIGHT_GRAY = 37


# ANSI modifiers
class AnsiModifier(Enum):
    NONE = 0
    BOLD = 1


# Logging formatter supporting colorized output
class LogFormatter(logging.Formatter):
    @staticmethod
    def color_escape_sequence(color: AnsiColor, modifier: AnsiModifier = 0):
        return f"\033[{modifier.value};{color.value}m"

    ANSI_STYLE = {
        logging.CRITICAL: (AnsiColor.PURPLE, AnsiModifier.BOLD),
        logging.ERROR: (AnsiColor.RED, AnsiModifier.BOLD),
        logging.WARNING: (AnsiColor.BROWN, AnsiModifier.BOLD),
        logging.INFO: (AnsiColor.LIGHT_GRAY, AnsiModifier.NONE),
        logging.DEBUG: (AnsiColor.BLACK, AnsiModifier.NONE),
    }

    RESET_CODE = "\033[0m"

    def __init__(self, use_color, *args, **kwargs):
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.use_color = use_color

    def format(self, record, *args, **kwargs):
        if self.use_color and record.levelno in self.ANSI_STYLE:
            record.style_on = LogFormatter.color_escape_sequence(
                *self.ANSI_STYLE.get(record.levelno,
                                     (AnsiColor.BLACK, AnsiModifier.BOLD))
            )
            record.style_off = self.RESET_CODE
        else:
            record.style_on = ""
            record.style_off = ""

        return super(LogFormatter, self).format(record, *args, **kwargs)


# straight from https://stackoverflow.com/questions/2183233/how-to-add-a-custom-loglevel-to-pythons-logging-facility
# /35804945#35804945
def add_logging_level(level_name, level_num, method_name=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not method_name:
        method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError('{} already defined in logging module'.format(level_name))
    if hasattr(logging, method_name):
        raise AttributeError('{} already defined in logging module'.format(method_name))
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError('{} already defined in logger class'.format(method_name))

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def log_for_level(self, message, *args, **kwargs):
        if self.isEnabledFor(level_num):
            self._log(level_num, message, args, **kwargs)

    def log_to_root(message, *args, **kwargs):
        logging.log(level_num, message, *args, **kwargs)

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), method_name, log_for_level)
    setattr(logging, method_name, log_to_root)


add_logging_level('TRACE', logging.DEBUG - 5)


def loglevelname_to_loglevel(loglevelname):
    loglevelname = loglevelname.upper()
    if hasattr(logging, loglevelname):
        return getattr(logging, loglevelname)
    else:
        raise Exception(f"Invalid loglevel '{loglevelname}'")


# Setup logging
def setup_logging(args, file_prefix=''):
    logfile_file = args.logfile
    log_line_template = '%(style_on)s%(asctime)s.%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d %(funcName)s] %(message)s%(style_off)s'

    if not logfile_file:
        time = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
        time_formatted = time.replace(':', '_')
        pid = os.getpid()
        try:
            os.mkdir("logs")
        except Exception:
            pass
        if file_prefix:
            file_prefix = f"{file_prefix}-"
        logfile_file = f"logs/{file_prefix}{time_formatted}-{pid}.log"

    logger = logging.getLogger()
    if hasattr(logging, 'TRACE'):
        logger.setLevel(logging.TRACE)
    else:
        logger.setLevel(logging.DEBUG)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(loglevelname_to_loglevel(args.loglevel))
    console_formatter = LogFormatter(fmt=log_line_template, use_color=True,
                                     datefmt='%H:%M:%S')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Create log file handler
    if logfile_file:
        logfile_handler = WatchedFileHandler(logfile_file)

        logfile_handler.setLevel(loglevelname_to_loglevel(args.logfile_loglevel))
        logfile_formatter = LogFormatter(fmt=log_line_template, use_color=False,
                                         datefmt='%H:%M:%S')
        logfile_handler.setFormatter(logfile_formatter)
        logger.addHandler(logfile_handler)

        logging.info(f"Logging to {logfile_file}")
