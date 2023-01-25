#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
test_something
--------------
"""

import unittest
from typing import Callable

from modpypes3.debugging import modpypes_debugging, ModuleLogger

# some debugging
_debug = 0
_log = ModuleLogger(globals())


@modpypes_debugging
class TestSomething(unittest.TestCase):

    _debug: Callable[..., None]

    def setUp(self) -> None:
        if _debug:
            TestSomething._debug("setUp")

    def test_something(self) -> None:
        if _debug:
            TestSomething._debug("test_something")

    def tearDown(self) -> None:
        if _debug:
            TestSomething._debug("tearDown")
