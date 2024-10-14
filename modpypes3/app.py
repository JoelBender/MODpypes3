"""
MODBUS Application Layer
"""

from __future__ import annotations

import asyncio
import struct
from collections import defaultdict

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Union

from .debugging import modpypes_debugging, ModuleLogger

from .comm import Client, Server
from .pdu import Address, PDU
from .errors import DecodingError

from .mpdu import (
    MBAP,
    MPDU,
    data_types,
    request_types,
    response_types,
    ReadCoilsRequest,
    ReadCoilsResponse,
    ReadDiscreteInputsRequest,
    ReadDiscreteInputsResponse,
    ReadInputRegistersRequest,
    ReadInputRegistersResponse,
    ReadHoldingRegistersRequest,
    ReadHoldingRegistersResponse,
    ExceptionResponse,
)

if TYPE_CHECKING:
    # class is declared as generic in stubs but not at runtime
    MPDUFuture = asyncio.Future[MPDU]
else:
    MPDUFuture = asyncio.Future

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# settings
CONNECTION_TIMEOUT = 2.0
READ_TIMEOUT = 0.5

#
#   ClientCodec
#


@modpypes_debugging
class ClientCodec(Client[PDU], Server[MPDU]):
    """
    Instances of this class are downstream of a client application and upstream
    of a TCPClientActor.
    """

    _debug: Callable[..., None]
    data_buffer: Dict[Address, bytes]

    def __init__(self, cid=None, sid=None) -> None:
        if _debug:
            ClientCodec._debug("__init__ cid=%r sid=%r", cid, sid)
        Client.__init__(self, cid)
        Server.__init__(self, sid)

        self.data_buffer = defaultdict(bytes)

    async def indication(self, mpdu: MPDU) -> None:
        """
        Downstream PDUs are requests.
        """
        if _debug:
            ClientCodec._debug("indication %r", mpdu)

        # encode it as a PDU
        pdu = mpdu.encode()
        if _debug:
            ClientCodec._debug("    - pdu: %r", pdu)

        # send it downstream
        await self.request(pdu)

    async def confirmation(self, pdu: PDU) -> None:
        """
        Upstream PDUs are responses, chunks of a TCP stream which may be
        incomplete.  Before attempting to decode them, make sure the entire
        MPDU has been received.
        """
        if _debug:
            ClientCodec._debug("confirmation %r", pdu)
        assert pdu.pduSource

        # check for closed connection message
        if not pdu.pduData:
            if pdu.pduSource in self.data_buffer:
                del self.data_buffer[pdu.pduSource]
            return

        # append the content to the buffer, see if there's enough
        data = self.data_buffer[pdu.pduSource] + pdu.pduData
        if len(data) < 7:
            if _debug:
                ClientCodec._debug("    - not enough data")
            self.data_buffer[pdu.pduSource] = data
            return

        # unpack the length
        pktlen = struct.unpack(">H", data[4:6])[0] + 6
        if len(data) < pktlen:
            if _debug:
                ClientCodec._debug(
                    "    - still not enough data: %r < %r", len(data), pktlen
                )
            self.data_buffer[pdu.pduSource] = data
            return

        self.data_buffer[pdu.pduSource] = data[pktlen:]
        pdu.pduData = bytearray(data[:pktlen])

        # decode the header
        mbap = MBAP.decode(pdu)

        # find the appropriate MPDU subclass by extracting the function
        # code, the first octet after the MBAP and part of the MPDU rather
        # than the header
        try:
            mpdu_function_code = pdu.pduData[0]
            if mpdu_function_code >= 128:
                mpdu_class = ExceptionResponse
            else:
                mpdu_class = response_types[mpdu_function_code]
        except KeyError:
            raise DecodingError(f"unrecognized MPDU function: {mpdu_function_code}")
        if _debug:
            ClientCodec._debug("    - mpdu_class: %r", mpdu_class)

        # ask the subclass to decode the rest of the pdu
        mpdu = mpdu_class.decode(pdu)
        if _debug:
            ClientCodec._debug("    - decoded: %r", mpdu)

        MBAP.update(mpdu, mbap)
        if _debug:
            ClientCodec._debug("    - mpdu: %r", mpdu)

        # send it upstream
        await self.response(mpdu)


#
#   ServerCodec
#


@modpypes_debugging
class ServerCodec(Client[MPDU], Server[PDU]):
    """
    Instances of this class are downstream of a TCPServerActor and upstream
    of a server application.
    """

    _debug: Callable[..., None]
    data_buffer: Dict[Address, bytes]

    def __init__(self, cid=None, sid=None) -> None:
        if _debug:
            ServerCodec._debug("__init__ cid=%r sid=%r", cid, sid)
        Client.__init__(self, cid)
        Server.__init__(self, sid)

        self.data_buffer = defaultdict(bytes)

    async def indication(self, pdu: PDU) -> None:
        """
        Downstream PDUs are requests, chunks of a TCP stream which may be
        incomplete.  Before attempting to decode them, make sure the entire
        MPDU has been received.
        """
        if _debug:
            ServerCodec._debug("indication %r", pdu)
        assert pdu.pduSource

        # check for closed connection message
        if not pdu.pduData:
            if pdu.pduSource in self.data_buffer:
                del self.data_buffer[pdu.pduSource]
            return

        # append the content to the buffer, see if there's enough
        data = self.data_buffer[pdu.pduSource] + pdu.pduData
        if len(data) < 7:
            self.data_buffer[pdu.pduSource] = data
            return

        # unpack the length
        pktlen = struct.unpack(">H", data[4:6])[0] + 6
        if len(data) < pktlen:
            self.data_buffer[pdu.pduSource] = data
            return

        self.data_buffer[pdu.pduSource] = data[pktlen:]
        pdu.pduData = bytearray(data[:pktlen])

        # decode the header
        mbap = MBAP.decode(pdu)

        # find the appropriate MPDU subclass by extracting the function
        # code, the first octet after the MBAP and part of the MPDU rather
        # than the header
        try:
            mpdu_function_code = pdu.pduData[0]
            mpdu_class = request_types[mpdu_function_code]
        except KeyError:
            raise DecodingError(f"unrecognized MPDU function: {mpdu_function_code}")
        if _debug:
            ServerCodec._debug("    - mpdu_class: %r", mpdu_class)

        # ask the subclass to decode the rest of the pdu
        mpdu = mpdu_class.decode(pdu)
        MBAP.update(mpdu, mbap)
        if _debug:
            ServerCodec._debug("    - mpdu: %r", mpdu)

        # send it downstream
        await self.request(mpdu)

    async def confirmation(self, mpdu: MPDU) -> None:
        """
        Upstream MPDUs are responses, encode them as generic PDUs and send
        them upstream.
        """
        if _debug:
            ServerCodec._debug("confirmation %r", mpdu)

        # encode it as a PDU
        pdu = mpdu.encode()
        if _debug:
            ServerCodec._debug("    - pdu: %r", pdu)

        # send it upstream
        await self.response(pdu)


@modpypes_debugging
class ClientApplication:
    """
    MODBUS Client
    """

    _debug: Callable[..., None]
    next_invoke_id: int

    server_address: Tuple[str, int]
    client_address: Tuple[str, int]

    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]

    def __init__(self, server_address: Tuple[str, int]):
        self.server_address = server_address
        self.next_invoke_id = 0
        self.reader = None
        self.writer = None

    async def __aenter__(self):
        """
        Open the connection when the context manager is entered.
        """
        if _debug:
            ClientApplication._debug("__aenter__")
        await self.open_connection()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """
        Close the connection when the context manager exits.
        """
        if _debug:
            ClientApplication._debug("__aexit__ %r %r %r", exc_type, exc, tb)
        await self.close_connection()

    async def open_connection(self):
        """
        Open a TCP connection to the IP-to-serial gateway that is connected to
        a MODBUS device.  Many modern MODBUS devices have a virtual serial bus.
        """
        if _debug:
            ClientApplication._debug("open_connection")

        host, port = self.server_address

        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
            ),
            timeout=CONNECTION_TIMEOUT,
        )
        if _debug:
            ClientApplication._debug(
                "    - reader, writer: %r %r", self.reader, self.writer
            )

        self.client_address = self.writer.get_extra_info("sockname")
        if _debug:
            ClientApplication._debug("    - client_address: %r", self.client_address)

    async def write(self, mpdu: MPDU) -> None:
        """
        Send a request to a MODBUS device
        """
        if _debug:
            ClientApplication._debug("request %r", mpdu)
        if not self.writer:
            raise RuntimeError("no connection")

        # make sure the trasnaction identifier is set
        if mpdu.mbapTransactionID is None:
            mpdu.mbapTransactionID = self.next_invoke_id
            self.next_invoke_id = (self.next_invoke_id + 1) % 256

        pdu = mpdu.encode()
        if _debug:
            ClientApplication._debug("    - pdu: %r", pdu)

        self.writer.write(pdu.pduData)
        if _debug:
            ClientApplication._debug("    - written")

        await self.writer.drain()
        if _debug:
            ClientApplication._debug("    - drained")

    async def read(self) -> MPDU:
        if _debug:
            ClientApplication._debug("read")
        if not self.reader:
            raise RuntimeError("no connection")

        # read the header
        header = await asyncio.wait_for(self.reader.read(6), timeout=READ_TIMEOUT)
        if _debug:
            ClientApplication._debug("    - header: %r", header)

        # the data length is in the header
        data_len = struct.unpack(">H", header[4:6])[0]

        # read the data
        data = await asyncio.wait_for(self.reader.read(data_len), timeout=READ_TIMEOUT)
        if _debug:
            ClientApplication._debug("    - data: %r", data)

        # put them both together before drinking it up
        pdu = PDU(
            header + data,
            source=self.server_address,
            destination=self.client_address,
        )
        if _debug:
            ClientApplication._debug("    - pdu: %r", pdu)

        # decode the header
        mbap = MBAP.decode(pdu)

        # find the appropriate MPDU subclass by extracting the function
        # code, the first octet after the MBAP and part of the MPDU rather
        # than the header
        try:
            mpdu_function_code = pdu.pduData[0]
            if mpdu_function_code >= 128:
                mpdu_class = ExceptionResponse
            else:
                mpdu_class = response_types[mpdu_function_code]
        except KeyError:
            raise DecodingError(f"unrecognized MPDU function: {mpdu_function_code}")
        if _debug:
            ClientApplication._debug("    - mpdu_class: %r", mpdu_class)

        # ask the subclass to decode the rest of the pdu
        mpdu = mpdu_class.decode(pdu)
        if _debug:
            ClientApplication._debug("    - decoded: %r", mpdu)

        MBAP.update(mpdu, mbap)
        if _debug:
            ClientApplication._debug("    - mpdu: %r", mpdu)

        # return the result
        return mpdu

    async def close_connection(self) -> None:
        if _debug:
            ClientApplication._debug("close_connection")
        if not self.writer:
            if _debug:
                ClientApplication._debug("    - already closed")
            return

        # close the writer
        self.writer.close()
        if _debug:
            ClientApplication._debug("    - closing")

        await self.writer.wait_closed()
        if _debug:
            ClientApplication._debug("    - closed")

        # a little protection against trying again
        self.reader = self.writer = None

    async def read_coils(
        self, unit_id: int, address: int, count: int
    ) -> Union[List[int], ExceptionResponse]:
        if _debug:
            ClientApplication._debug("read_coils %r %r %r", unit_id, address, count)

        # build a request
        mpdu = ReadCoilsRequest(
            unit_id=unit_id,
            address=address,
            count=count,
        )
        if _debug:
            ClientApplication._debug("    - mpdu: %r", mpdu)

        # send the request
        await self.write(mpdu)

        # read the response
        response = await self.read()
        if _debug:
            ClientApplication._debug("    - response: %r", response)
        if isinstance(response, ExceptionResponse):
            return response

        assert isinstance(response, ReadCoilsResponse)

        # return the values
        return response.values

    async def read_descrete_inputs(
        self, unit_id: int, address: int, count: int
    ) -> Union[List[int], ExceptionResponse]:
        if _debug:
            ClientApplication._debug(
                "read_descrete_inputs %r %r %r", unit_id, address, count
            )

        # build a request
        mpdu = ReadDiscreteInputsRequest(
            unit_id=unit_id,
            address=address,
            count=count,
        )
        if _debug:
            ClientApplication._debug("    - mpdu: %r", mpdu)

        # send the request
        await self.write(mpdu)

        # read the response
        response = await self.read()
        if _debug:
            ClientApplication._debug("    - response: %r", response)
        if isinstance(response, ExceptionResponse):
            return response

        assert isinstance(response, ReadDiscreteInputsResponse)

        # return the values
        return response.bits

    async def read_holding_registers(
        self, unit_id: int, address: int, count: int
    ) -> Union[List[int], ExceptionResponse]:
        if _debug:
            ClientApplication._debug(
                "read_holding_registers %r %r %r", unit_id, address, count
            )

        # build a request
        mpdu = ReadHoldingRegistersRequest(
            unit_id=unit_id,
            address=address,
            count=count,
        )
        if _debug:
            ClientApplication._debug("    - mpdu: %r", mpdu)

        # send the request
        await self.write(mpdu)

        # read the response
        response = await self.read()
        if _debug:
            ClientApplication._debug("    - response: %r", response)
        if isinstance(response, ExceptionResponse):
            return response

        assert isinstance(response, ReadHoldingRegistersResponse)

        # return the registers
        return response.registers

    async def read_input_registers(
        self, unit_id: int, address: int, count: int
    ) -> Union[List[int], ExceptionResponse]:
        if _debug:
            ClientApplication._debug(
                "read_input_registers %r %r %r", unit_id, address, count
            )

        # build a request
        mpdu = ReadInputRegistersRequest(
            unit_id=unit_id,
            address=address,
            count=count,
        )
        if _debug:
            ClientApplication._debug("    - mpdu: %r", mpdu)

        # send the request
        await self.write(mpdu)

        # read the response
        response = await self.read()
        if _debug:
            ClientApplication._debug("    - response: %r", response)
        if isinstance(response, ExceptionResponse):
            return response

        assert isinstance(response, ReadInputRegistersResponse)

        # return the registers
        return response.registers


@modpypes_debugging
class ServerApplication(Server[PDU]):
    """
    MODBUS Server
    """

    _debug: Callable[..., None]

    unit_number: int
    register_map: Dict[int, Tuple[str, Any]]

    def __init__(self, unit_number: int, register_map: Dict[int, Tuple[str, Any]]):
        if _debug:
            ServerApplication._debug("__init__ %r", unit_number)

        self.unit_number = unit_number
        self.register_map = register_map

    async def indication(self, mpdu: MPDU) -> None:
        """
        Downstream MPDUs are requests.
        """
        if _debug:
            ServerApplication._debug("indication %r", mpdu)

        if mpdu.mbapUnitID != self.unit_number:
            if _debug:
                ServerApplication._debug("    - not for us")

        fn = getattr(self, "do_" + mpdu.__class__.__name__, None)
        if not fn:
            if _debug:
                ServerApplication._debug("    - no function")
            return

        await fn(mpdu)

    async def do_ReadHoldingRegistersRequest(
        self, mpdu: ReadHoldingRegistersRequest
    ) -> None:
        if _debug:
            ServerApplication._debug("do_ReadHoldingRegistersRequest %r", mpdu)

        register_address = mpdu.address + 40000 + 1
        if register_address not in self.register_map:
            if _debug:
                ServerApplication._debug("    - no register")
            return
        if _debug:
            ServerApplication._debug("    - register_address: %r", register_address)

        # pull the values out of the register map
        register_datatype, register_value = self.register_map[register_address]
        if _debug:
            ServerApplication._debug(
                "    - register_datatype, register_value: %r, %r",
                register_datatype,
                register_value,
            )

        datatype = data_types[register_datatype]
        if _debug:
            ServerApplication._debug("    - datatype: %r", datatype)

        packed_value = datatype.pack(register_value)
        if _debug:
            ServerApplication._debug("    - packed_value: %r", packed_value)

        response = ReadHoldingRegistersResponse(
            packed_value,
            destination=mpdu.pduSource,
        )
        if _debug:
            ServerApplication._debug("    - response: %r", response)

        # return the response
        await self.response(response)
