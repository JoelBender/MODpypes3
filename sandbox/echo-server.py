#!/usr/bin/python3.6

from __future__ import annotations

import asyncio
import logging

from typing import Callable

from modpypes3.settings import settings
from modpypes3.debugging import modpypes_debugging, ModuleLogger
from modpypes3.argparse import ArgumentParser

from modpypes3.comm import Server, bind
from modpypes3.pdu import IPv4Address, PDU
from modpypes3.ipv4.tcp import TCPServerDirector

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# logging
_log = logging.getLogger(__name__)


@modpypes_debugging
class ServerApp(Server[PDU]):

    _debug: Callable[..., None]

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            ServerApp._debug("indication %r", pdu)

        response_data = pdu.pduData.decode().upper().encode()
        await self.response(
            PDU(response_data, source=pdu.pduDestination, destination=pdu.pduSource)
        )


async def main():
    ArgumentParser().parse_args()
    if _debug:
        _log.debug("settings: %r", settings)

    # build some small stacks
    directors = []
    for port in range(8888, 8890):
        director = TCPServerDirector(IPv4Address(f"127.0.0.1:{port}"))
        server = ServerApp()
        bind(director, server)

        directors.append(director.serve_forever())

    await asyncio.gather(*directors)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
