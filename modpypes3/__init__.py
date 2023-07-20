"""
MODBUS Python Package
"""

#
#   Platform Check
#

import sys as _sys
import warnings as _warnings

_supported_platforms = ("linux", "win32", "darwin")

if _sys.platform not in _supported_platforms:
    _warnings.warn("unsupported platform", RuntimeWarning)

#
#   Project Metadata
#

__version__ = "0.5"
__author__ = "Joel Bender"
__email__ = "joel@carrickbender.com"

#
#   Settings and Debugging
#

from . import settings
from . import debugging
from . import errors

#
#   Communications Core Modules
#

from . import pdu
from . import comm

#
#   Shell
#

from . import argparse
from . import console
from . import cmd

#
#   Application Layer
#

from . import app
from . import mpdu

#
#   Transport
#

from . import ipv4
