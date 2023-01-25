#!/usr/bin/python

"""
Simple console example.
"""

from __future__ import annotations

import sys
import asyncio

from typing import Callable, Optional

from modpypes3.settings import settings
from modpypes3.debugging import modpypes_debugging, ModuleLogger
from modpypes3.argparse import ArgumentParser

from modpypes3.comm import Client, Server, bind
from modpypes3.console import Console, ConsolePDU
from modpypes3.pdu import IPv4Address, PDU
from modpypes3.ipv4.tcp import TCPClientDirector

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
tcp_client_director: TCPClientDirector


@modpypes_debugging
class ConsoleApp(Client[PDU], Server[ConsolePDU]):

    _debug: Callable[..., None]

    async def indication(self, pdu: ConsolePDU) -> None:
        """
        This function is called with each line of text from the console (or
        from a file or pipe) and called with None at end-of-file.  It is
        "downstream" of the Console() instance and gets this "indication" when
        the console is making a "request".
        """
        if _debug:
            ConsoleApp._debug("indication %r", pdu)
        global tcp_client_director

        if pdu is None:
            await tcp_client_director.close_connections()
            return

        assert isinstance(pdu, str)

        if pdu == "sleep":
            await asyncio.sleep(1.0)
            return

        try:
            addr, message = pdu.split(" ", 1)
            server_address = IPv4Address(addr)
        except ValueError:
            await self.response("host:port message")
            return

        # send downstream to the director
        await self.request(PDU(message.encode(), destination=server_address))

    async def confirmation(self, pdu: PDU) -> None:
        """
        When receiving a PDU upstream from the director, turn it into a string
        so it can continue upstream to the console.
        """
        if _debug:
            ConsoleApp._debug("confirmation %r", pdu)

        await self.response(str(pdu))


async def main() -> None:
    global tcp_client_director

    try:
        console: Optional[Console] = None
        ArgumentParser().parse_args()
        if _debug:
            _log.debug("settings: %r", settings)

        # build a very small stack
        console = Console()
        console_app = ConsoleApp()
        tcp_client_director = TCPClientDirector()
        if _debug:
            _log.debug("console, tcp_client: %r, %r", console, tcp_client_director)

        # bind the two objects together, top down
        bind(console, console_app, tcp_client_director)  # type: ignore[misc]

        # run until the console is done, canceled or EOF
        await console.fini.wait()

    finally:
        if console and console.exit_status:
            sys.exit(console.exit_status)


if __name__ == "__main__":
    asyncio.run(main())
