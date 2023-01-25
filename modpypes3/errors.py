"""
Errors
"""

from __future__ import annotations

from typing import Any

#
#   ConfigurationError
#


class ConfigurationError(ValueError):

    """This error is raised when there is a configuration problem such as
    bindings between layers or required parameters that are missing.
    """

    def __init__(self, *args: Any) -> None:
        self.args = args


#
#   Encoding and Decoding
#


class EncodingError(ValueError):

    """This error is raised if there is a problem during encoding."""

    def __init__(self, *args: Any) -> None:
        self.args = args


class DecodingError(ValueError):

    """This error is raised if there is a problem during decoding."""

    def __init__(self, *args: Any) -> None:
        self.args = args
