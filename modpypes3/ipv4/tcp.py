#!/usr/bin/python

"""
TCP
"""

from __future__ import annotations

import asyncio

from asyncio.exceptions import TimeoutError, CancelledError

from typing import Callable, Dict, Optional

from modpypes3.debugging import modpypes_debugging, ModuleLogger
from modpypes3.comm import Client, Server
from modpypes3.pdu import IPv4Address, PDU

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# settings
IDLE_TIMEOUT = 1.500
READ_BUFFER_SIZE = 1500


@modpypes_debugging
class TCPClientActor:
    """ """

    _debug: Callable[..., None]

    director: TCPClientDirector
    server_address: IPv4Address
    client_address: Optional[IPv4Address]

    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]
    _read_task: Optional[asyncio.Task]

    def __init__(
        self, director: TCPClientDirector, server_address: IPv4Address
    ) -> None:
        if _debug:
            TCPClientActor._debug("__init__() %r %r", director, server_address)

        # reference to upstream director
        self.director = director

        # save the server address, client address available when the connection
        # is open
        self.server_address = server_address
        self.client_address = None
        self.reader = None
        self.writer = None

        # no read task until the client is connected
        self._read_task = None

    async def open_connection(self) -> bool:
        """
        Open a connection to the server, return True if the connection is
        established.
        """
        if _debug:
            TCPClientActor._debug("open_connection(%s)", self.client_address)

        try:
            host, port = self.server_address.addrTuple
            self.reader, self.writer = await asyncio.open_connection(
                host,
                port,
            )
            if _debug:
                TCPClientActor._debug(
                    "    - reader, writer: %r %r", self.reader, self.writer
                )
        except OSError as err:
            if _debug:
                TCPClientActor._debug("    - OSError: %r", err)
            return False
        except ConnectionRefusedError:
            if _debug:
                TCPClientActor._debug("    - connection refused")
            return False
        except CancelledError:
            if _debug:
                TCPClientActor._debug("    - connection canceled")
            return False

        self.client_address = IPv4Address(self.writer.get_extra_info("sockname"))
        if _debug:
            TCPClientActor._debug("    - client_address: %r", self.client_address)

        # start reading when you get a chance
        self._read_task = asyncio.create_task(self._read())
        self._read_task.add_done_callback(self._read_complete)

        # success
        return True

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            TCPClientActor._debug("indication(%s) %r", self.client_address, pdu)
        if not self.writer:
            raise RuntimeError("no writer")

        self.writer.write(pdu.pduData)
        if _debug:
            TCPClientActor._debug("    - written")

        await self.writer.drain()
        if _debug:
            TCPClientActor._debug("    - drained")

    async def _read(self):
        if _debug:
            TCPClientActor._debug("_read(%s)", self.client_address)
        if not self.reader:
            raise RuntimeError("no reader")

        running = True
        while running:
            try:
                data = b""
                if not self.reader:
                    if _debug:
                        TCPClientActor._debug("    - no reader")
                    break
                if _debug:
                    TCPClientActor._debug("    - reading")

                data = await asyncio.wait_for(
                    self.reader.read(READ_BUFFER_SIZE), timeout=IDLE_TIMEOUT
                )
                if _debug:
                    TCPClientActor._debug("    - received: %r", data)
            except TimeoutError:
                if _debug:
                    TCPClientActor._debug("    - timeout")
                break
            except CancelledError:
                if _debug:
                    TCPClientActor._debug("    - canceled")
                break

            # send this upstream
            if data:
                await self.response(
                    PDU(
                        data,
                        source=self.server_address,
                        destination=self.client_address,
                    )
                )

            if (not self.reader) or self.reader.at_eof():
                if _debug:
                    TCPClientActor._debug("    - end-of-file")
                break

        # all done
        await self.close_connection()

    def _read_complete(self, future: asyncio.Future) -> None:
        if _debug:
            TCPClientActor._debug("_read_complete(%s) %r", self.client_address, future)

    async def response(self, pdu: PDU) -> None:
        if _debug:
            TCPClientActor._debug("response %r", pdu)
        await self.director.response(pdu)

    async def close_connection(self) -> None:
        if _debug:
            TCPClientActor._debug("close_connection(%s)", self.client_address)
        if not self.writer:
            if _debug:
                TCPClientActor._debug("    - already closed")
            return

        # this may already be closed
        if self.server_address not in self.director.actors:
            if self.reader or self.writer:
                raise RuntimeWarning("already closed")
            if _debug:
                TCPClientActor._debug("    - already closed")
            return

        # tell the director we're out
        del self.director.actors[self.server_address]

        self.writer.close()
        if _debug:
            TCPClientActor._debug("    - closing")

        await self.writer.wait_closed()
        if _debug:
            TCPClientActor._debug("    - closed")

        # a little protection against trying again
        self.reader = self.writer = None

    def __repr__(self):
        return "<TCPClientActor " + str(self.client_address) + ">"


@modpypes_debugging
class TCPClientDirector(Server[PDU]):
    """ """

    _debug: Callable[..., None]

    actors: Dict[IPv4Address, TCPClientActor]

    def __init__(self):
        """ """
        if _debug:
            TCPClientDirector._debug("__init__")
        super().__init__()

        self.actors = {}

    async def indication(self, pdu: PDU) -> None:
        """
        Called with each downstream PDU, check to see if there is an actor that
        can accept this request or make a new one.
        """
        if _debug:
            TCPClientDirector._debug("indication %r", pdu)
        assert isinstance(pdu.pduDestination, IPv4Address)

        # find the actor associated with this request, and if there isn't
        # one, open a connection
        actor = self.actors.get(pdu.pduDestination, None)
        if not actor:
            actor = TCPClientActor(self, pdu.pduDestination)
            if not (await actor.open_connection()):
                if _debug:
                    TCPClientDirector._debug("    - no connection")
                return

            self.actors[pdu.pduDestination] = actor

        # the actor is receiving this as a request
        await actor.indication(pdu)

    async def close_connections(self):
        """
        Tell the running actors to close their connections.
        """
        if _debug:
            TCPClientDirector._debug("close_connections")

        # make list of coroutines for closing each actor
        closing_connections = list(
            actor.close_connection() for actor in self.actors.values()
        )
        if _debug:
            TCPClientDirector._debug(
                "    - closing_connections: %r", closing_connections
            )

        # wait for them to finish
        await asyncio.gather(*closing_connections)
        if _debug:
            TCPClientDirector._debug("    - connections closed")


@modpypes_debugging
class TCPServerActor:
    """ """

    _debug: Callable[..., None]

    director: TCPServerDirector
    client_address: IPv4Address
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]

    _read_task: asyncio.Task

    def __init__(
        self,
        director: TCPServerDirector,
        client_address: IPv4Address,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if _debug:
            TCPServerActor._debug(
                "__init__(%s) %r %r %r %r",
                client_address,
                director,
                client_address,
                reader,
                writer,
            )

        # reference to upstream director
        self.director = director

        # note this is the address of the client, not us as a server
        self.client_address = client_address
        self.reader = reader
        self.writer = writer

        # start reading when you get a chance
        self._read_task = asyncio.create_task(self._read())
        self._read_task.add_done_callback(self._read_complete)

    async def confirmation(self, pdu) -> None:
        if _debug:
            TCPServerActor._debug("confirmation(%s) %r", self.client_address, pdu)
        if not self.writer:
            raise RuntimeError("no writer")

        self.writer.write(pdu.pduData)
        if _debug:
            TCPServerActor._debug("    - written")

        await self.writer.drain()
        if _debug:
            TCPServerActor._debug("    - drained")

    async def _read(self) -> None:
        if _debug:
            TCPServerActor._debug("_read(%s)", self.client_address)
        if not self.reader:
            raise RuntimeError("no reader")

        running = True
        while running:
            try:
                data = b""
                if not self.reader:
                    if _debug:
                        TCPServerActor._debug("    - no reader")
                    break
                if _debug:
                    TCPServerActor._debug("    - reading")

                data = await asyncio.wait_for(
                    self.reader.read(READ_BUFFER_SIZE), timeout=IDLE_TIMEOUT
                )
                if _debug:
                    TCPServerActor._debug("    - received: %r", data)
            except TimeoutError:
                if _debug:
                    TCPServerActor._debug("    - timeout")
                break
            except CancelledError:
                if _debug:
                    TCPServerActor._debug("    - canceled")
                break

            # send this downstream
            if data:
                await self.request(
                    PDU(
                        data,
                        source=self.client_address,
                        destination=self.director.address,
                    )
                )

            if (not self.reader) or self.reader.at_eof():
                if _debug:
                    TCPServerActor._debug("    - end-of-file")
                break

        # all done
        await self.close_connection()

    def _read_complete(self, future: asyncio.Future) -> None:
        if _debug:
            TCPServerActor._debug("_read_complete(%s) %r", self.client_address, future)

        # suck out the exception but toss it
        exception = future.exception()
        if _debug:
            TCPServerActor._debug("    - exception: %s", exception)
            if exception:
                TCPServerActor._debug("    - args: %r", exception.args)

    async def request(self, pdu: PDU) -> None:
        """
        Send this request downstream as if it is coming from the director.  This
        is a separate method rather than this line being called directly from
        read() so it can be overridden.
        """
        if _debug:
            TCPServerActor._debug("request(%s) %r", self.client_address, pdu)
        await self.director.request(pdu)

    async def close_connection(self) -> None:
        if _debug:
            TCPServerActor._debug("close_connection(%s)", self.client_address)
        if not self.writer:
            if _debug:
                TCPServerActor._debug("    - already closed")
            return

        del self.director.actors[self.client_address]

        self.writer.close()
        if _debug:
            TCPServerActor._debug("    - closing")

        await self.writer.wait_closed()
        if _debug:
            TCPServerActor._debug("    - closed")

        # a little protection against trying again
        self.reader = self.writer = None

    def __repr__(self):
        return "<TCPServerActor " + str(self.client_address) + ">"


@modpypes_debugging
class TCPServerDirector(Client[PDU]):
    """ """

    _debug: Callable[..., None]

    address: IPv4Address
    actors: Dict[IPv4Address, TCPServerActor]

    def __init__(self, address: IPv4Address):
        """ """
        if _debug:
            TCPServerDirector._debug("__init__ %r", address)
        super().__init__()

        self.address = address
        self.actors = {}

    async def serve_forever(self) -> None:
        """
        Create an asyncio server bound to the (host, port).
        """
        if _debug:
            TCPServerDirector._debug("serve_forever")

        host, port = self.address.addrTuple
        server = await asyncio.start_server(self._new_connection, host, port)

        if _debug:
            addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
            TCPServerDirector._debug("    - serving on %s", addrs)

        async with server:
            await server.serve_forever()

    def _new_connection(self, reader, writer) -> None:
        if _debug:
            TCPServerDirector._debug("_new_connection %r %r", reader, writer)

        client_address = IPv4Address(writer.get_extra_info("peername"))
        if _debug:
            TCPServerDirector._debug("    - client_address: %r", client_address)
        if client_address in self.actors:
            raise RuntimeError("client address collision")

        # create an actor
        actor = TCPServerActor(self, client_address, reader, writer)
        if _debug:
            TCPServerDirector._debug("    - actor: %r", actor)

        self.actors[client_address] = actor

    async def confirmation(self, pdu: PDU) -> None:
        """
        Upstream PDUs are responses to a request.
        """
        if _debug:
            TCPServerDirector._debug("indication {!r}".format(pdu))
        assert isinstance(pdu.pduDestination, IPv4Address)

        actor = self.actors.get(pdu.pduDestination, None)
        if not actor:
            raise RuntimeError(f"no actor: {pdu.pduDestination}")

        await actor.confirmation(pdu)
