#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MODBUS Protocol Data Units
==========================
"""

from __future__ import annotations

import struct
from typing import Callable, Dict, List, Optional, Tuple, Type

from .debugging import modpypes_debugging, DebugContents, ModuleLogger

from .pdu import PCI, PDU, PDUData
from .errors import DecodingError

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# a dictionary of functions and classes
request_types: Dict[int, Type[MPDU]] = {}
response_types: Dict[int, Type[MPDU]] = {}
data_types: Dict[str, Type[DataType]]


def register_request_type(klass: Type[MPDU]) -> Type[MPDU]:
    assert hasattr(klass, "functionCode")
    request_types[klass.functionCode] = klass
    return klass


def register_response_type(klass: Type[MPDU]) -> Type[MPDU]:
    assert hasattr(klass, "functionCode")
    response_types[klass.functionCode] = klass
    return klass


#
#   Packing and Unpacking Functions
#


def _packBitsToString(bits):
    barry = []
    i = packed = 0
    for bit in bits:
        if bit:
            packed += 128
        i += 1
        if i == 8:
            barry.append(packed)
            i = packed = 0
        else:
            packed >>= 1
    if i > 0 and i < 8:
        packed >>= 7 - i
        barry.append(packed)
    return struct.pack("B" * len(barry), *barry)


def _unpackBitsFromString(string):
    barry = struct.unpack("B" * len(string), string)
    bits = []
    for byte in barry:
        for bit in range(8):
            bits.append((byte & 1) == 1)
            byte >>= 1
    return bits


#
#   Data Types
#


class DataType:

    """
    This is an abstract class for functions that pack and unpack the
    variably encoded portion of a PDU.  Each of the derived classes
    produces or consumes a number of 16-registers.
    """

    registerLength: int

    @classmethod
    def pack(cls, value):
        raise NotImplementedError("pack is not implemented in %s" % (cls.__name__,))

    @classmethod
    def unpack(cls, registers):
        raise NotImplementedError("unpack is not implemented in %s" % (cls.__name__,))


@modpypes_debugging
class Byte(DataType):

    """
    This class packs and unpacks a register as an unsigned octet.
    """

    _debug: Callable[..., None]

    registerLength = 1

    @classmethod
    def pack(cls, value):
        if _debug:
            Byte._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, int):
            try:
                value = int(value)
            except TypeError:
                Byte._error("coercion error: %r not an int", value)
                value = 0

        return [value & 0xFF]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            Byte._debug("unpack %r", registers)

        return registers[0]


@modpypes_debugging
class Int(DataType):

    """
    This class packs and unpacks a register as a 16-bit signed integer.
    """

    _debug: Callable[..., None]

    registerLength = 1

    @classmethod
    def pack(cls, value):
        if _debug:
            Int._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, int):
            try:
                value = int(value)
            except TypeError:
                Int._error("coercion error: %r not an int", value)
                value = 0

        return [value & 0xFFFF]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            Int._debug("unpack %r", registers)

        value = registers[0]
        if value & 0x8000:
            value = (-1 << 16) | value

        return value


@modpypes_debugging
class UnsignedInt(DataType):

    """
    This class packs and unpacks a register as a 16-bit unsigned integer.
    """

    _debug: Callable[..., None]

    registerLength = 1

    @classmethod
    def pack(cls, value):
        if _debug:
            UnsignedInt._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, int):
            try:
                value = int(value)
            except TypeError:
                UnsignedInt._error("coercion error: %r not an int", value)
                value = 0

        return [value & 0xFFFF]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            UnsignedInt._debug("unpack %r", registers)

        return registers[0]


@modpypes_debugging
class DoubleInt(DataType):

    """
    This class packs and unpacks a pair of registers as a 32-bit signed integer.
    """

    registerLength = 2

    @classmethod
    def pack(cls, value):
        if _debug:
            DoubleInt._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, int):
            try:
                value = int(value)
            except TypeError:
                DoubleInt._error("coercion error: %r not an int", value)
                value = 0

        return [(value >> 16) & 0xFFFF, value & 0xFFFF]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            DoubleInt._debug("unpack %r", registers)

        value = (registers[0] << 16) | registers[1]
        if value & 0x80000000:
            value = (-1 << 32) | value

        return value


@modpypes_debugging
class UnsignedDoubleInt(DataType):

    """
    This class packs and unpacks a pair of registers as a 32-bit unsigned integer.
    """

    _debug: Callable[..., None]

    registerLength = 2

    @classmethod
    def pack(cls, value):
        if _debug:
            UnsignedDoubleInt._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, int):
            try:
                value = int(value)
            except TypeError:
                UnsignedDoubleInt._error("coercion error: %r not an int", value)
                value = 0

        return [(value >> 16) & 0xFFFF, value & 0xFFFF]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            UnsignedDoubleInt._debug("unpack %r", registers)

        return (registers[0] << 16) | registers[1]


@modpypes_debugging
class Real(DataType):

    registerLength = 2

    @classmethod
    def pack(cls, value):
        if _debug:
            Real._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, float):
            try:
                value = float(value)
            except TypeError:
                BigEndianReal._error("coercion error: %r not a float", value)
                value = 0.0

        registers = struct.unpack(">HH", struct.pack(">f", value))
        return [registers[1], registers[0]]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            Real._debug("unpack %r", registers)

        (value,) = struct.unpack(">f", struct.pack(">HH", registers[1], registers[0]))
        return value


@modpypes_debugging
class ROCReal(DataType):
    _debug: Callable[..., None]

    registerLength = 1

    @classmethod
    def pack(cls, value):
        if _debug:
            ROCReal._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, float):
            try:
                value = float(value)
            except TypeError:
                ROCReal._error("coercion error: %r not a float", value)
                value = 0.0

        raise NotImplementedError("packing ROCReal is not supported")

    @classmethod
    def unpack(cls, registers):
        if _debug:
            ROCReal._debug("unpack %r", registers)

        # byte-swap the registers
        r0, r1 = registers
        r0 = ((r0 & 0xFF00) >> 8) | ((r0 & 0x00FF) << 8)
        r1 = ((r1 & 0xFF00) >> 8) | ((r1 & 0x00FF) << 8)

        (value,) = struct.unpack(">f", struct.pack(">HH", r1, r0))
        return value


@modpypes_debugging
class BigEndianDoubleInt(DataType):

    """
    This class packs and unpacks a pair of registers as a bit endian 32-bit signed integer.
    """

    _debug: Callable[..., None]

    registerLength = 2

    @classmethod
    def pack(cls, value):
        if _debug:
            BigEndianDoubleInt._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, int):
            try:
                value = int(value)
            except TypeError:
                BigEndianDoubleInt._error("coercion error: %r not an int", value)
                value = 0

        return [value & 0xFFFF, (value >> 16) & 0xFFFF]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            BigEndianDoubleInt._debug("unpack %r", registers)

        value = (registers[1] << 16) | registers[0]
        if value & 0x80000000:
            value = (-1 << 32) | value

        return value


@modpypes_debugging
class BigEndianUnsignedDoubleInt(DataType):

    """
    This class packs and unpacks a pair of registers as a bit endian 32-bit unsigned integer.
    """

    _debug: Callable[..., None]

    registerLength = 2

    @classmethod
    def pack(cls, value):
        if _debug:
            BigEndianUnsignedDoubleInt._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, int):
            try:
                value = int(value)
            except TypeError:
                BigEndianUnsignedDoubleInt._error(
                    "coercion error: %r not an int", value
                )
                value = 0

        return [value & 0xFFFF, (value >> 16) & 0xFFFF]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            BigEndianUnsignedDoubleInt._debug("unpack %r", registers)

        return (registers[1] << 16) | registers[0]


@modpypes_debugging
class BigEndianReal(DataType):
    _debug: Callable[..., None]

    registerLength = 2

    @classmethod
    def pack(cls, value):
        if _debug:
            BigEndianReal._debug("pack %r", value)

        # convert the value if necessary
        if not isinstance(value, float):
            try:
                value = float(value)
            except TypeError:
                BigEndianReal._error("coercion error: %r not a float", value)
                value = 0.0

        registers = struct.unpack(">HH", struct.pack(">f", value))
        return [registers[0], registers[1]]

    @classmethod
    def unpack(cls, registers):
        if _debug:
            BigEndianReal._debug("unpack %r", registers)

        (value,) = struct.unpack(">f", struct.pack(">HH", registers[0], registers[1]))
        return value


@modpypes_debugging
class String(DataType):

    """
    This class packs and unpacks a list of registers as a null terminated string.
    """

    _debug: Callable[..., None]

    def __init__(self, registerLength=6):
        if _debug:
            String._debug("__init__ %r", registerLength)

        # save the length
        self.registerLength = registerLength

    @classmethod
    def pack(cls, value):
        if _debug:
            String._debug("pack %r", value)
        raise NotImplementedError("packing strings is not implemeted")

    @classmethod
    def unpack(cls, registers):
        if _debug:
            String._debug("unpack %r", registers)

        octets = []
        for reg in registers:
            octets.append(reg >> 8)
            octets.append(reg & 0xFF)

        value = "".join(chr(c) for c in octets)
        value = value[: value.find("\x00")]
        return value


@modpypes_debugging
class BigEndianString(DataType):

    """
    This class packs and unpacks a list of registers as a null terminated string.
    """

    _debug: Callable[..., None]

    def __init__(self, registerLength=6):
        if _debug:
            BigEndianString._debug("__init__ %r", registerLength)

        # save the length
        self.registerLength = registerLength

    @classmethod
    def pack(cls, value):
        if _debug:
            BigEndianString._debug("pack %r", value)
        raise NotImplementedError("packing strings is not implemeted")

    @classmethod
    def unpack(cls, registers):
        if _debug:
            BigEndianString._debug("unpack %r", registers)

        octets = []
        for reg in registers:
            octets.append(reg & 0xFF)
            octets.append(reg >> 8)

        value = "".join(chr(c) for c in octets)
        value = value[: value.find("\x00")]
        return value


data_types = {
    "byte": Byte,
    "int": Int,
    "uint": UnsignedInt,
    "dint": DoubleInt,
    "udint": UnsignedDoubleInt,
    "be-dint": BigEndianDoubleInt,
    "be-udint": BigEndianUnsignedDoubleInt,
    "real": Real,
    "roc-real": ROCReal,
    "be-real": BigEndianReal,
    "str": String,
    "be-str": BigEndianString,
}

#
#  MBAP
#


@modpypes_debugging
class MBAP(PCI, DebugContents):

    """
    This class contains the MODBUS protocol control information which
    is the 6 octet header at the front of all MODBUS PDUs.

    WARNING: Lark's Vomit

    The length field indicates the number of octets after the length
    field, even though the unit identifier is part of the header but the
    function code that follows is not.
    """

    _debug_contents: Tuple[str, ...] = (
        "mbapTransactionID",
        "mbapProtocolID",
        "mbapLength",
        "mbapUnitID",
    )

    def __init__(
        self,
        *args,
        transaction_id: Optional[int] = 0,
        protocol_id: Optional[int] = 0,
        length: Optional[int] = 0,
        unit_id: Optional[int] = 0,
        **kwargs,
    ):
        if _debug:
            MBAP._debug("__init__ %r %r", args, kwargs)
        PCI.__init__(self, *args, **kwargs)
        self.mbapTransactionID = transaction_id
        self.mbapProtocolID = protocol_id
        self.mbapLength = length
        self.mbapUnitID = unit_id

    def update(self, mbap):
        if _debug:
            MBAP._debug("update %r", mbap)

        PCI.update(self, mbap)
        self.mbapTransactionID = mbap.mbapTransactionID
        self.mbapProtocolID = mbap.mbapProtocolID
        self.mbapLength = mbap.mbapLength
        self.mbapUnitID = mbap.mbapUnitID

    def encode(self) -> PDU:
        if _debug:
            MBAP._debug("encode")
        assert self.mbapTransactionID is not None
        assert self.mbapProtocolID is not None
        assert self.mbapLength is not None
        assert self.mbapUnitID is not None

        pdu = PDU()
        PCI.update(pdu, self)
        pdu.put_short(self.mbapTransactionID)
        pdu.put_short(self.mbapProtocolID)
        pdu.put_short(self.mbapLength)
        pdu.put(self.mbapUnitID)

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MBAP:  # type: ignore[override]
        if _debug:
            MBAP._debug("decode %r", pdu)

        mbap = MBAP()
        PCI.update(mbap, pdu)

        mbap.mbapTransactionID = pdu.get_short()
        mbap.mbapProtocolID = pdu.get_short()
        mbap.mbapLength = pdu.get_short()
        if mbap.mbapLength != len(pdu.pduData):
            raise DecodingError("invalid length")

        # part of the header
        mbap.mbapUnitID = pdu.get()

        return mbap


#
#   MPDU
#


@modpypes_debugging
class MPDU(MBAP, PDUData):

    """
    This class is a generic MODBUS PDU.  It inherits the :class:`MBAP`
    layer and the more generic PDU data functions.
    """

    _debug_contents: Tuple[str, ...] = ("functionCode",)

    functionCode: int

    readCoils = 1
    readDiscreteInputs = 2
    readHoldingRegisters = 3
    readInputRegisters = 4
    writeSingleCoil = 5
    writeSingleRegister = 6
    writeMultipleCoils = 15
    writeMultipleRegisters = 16
    readWriteMultipleRegisters = 23
    announceMaster = 100
    registerSlave = 105

    def __init__(self, *args, function_code: int, **kwargs):
        if _debug:
            MPDU._debug("__init__ %r function_code=%r %r", args, function_code, kwargs)

        MBAP.__init__(self, **kwargs)
        PDUData.__init__(self, *args)

        self.functionCode = function_code

    def update(self, mpdu):
        if _debug:
            MPDU._debug("update %r", mpdu)

        MBAP.update(self, mpdu)
        self.functionCode = mpdu.functionCode

    def encode(self) -> PDU:
        if _debug:
            MPDU._debug("encode")

        pdu = MBAP.encode(self)
        pdu.put(self.functionCode)
        if _debug:
            MPDU._debug("    - pdu: %r", pdu)

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MPDU:  # type: ignore[override]
        raise NotImplementedError("overridden")


# ------------------------------


@modpypes_debugging
class ReadBitsRequestBase(MPDU, DebugContents):

    """
    Base class for messages requesting bit values.  This is inherited by
    both :class:`ReadCoilsRequest` and :class:`ReadDiscreteInputsRequest`.
    """

    _debug_contents = ("address", "count")

    def __init__(
        self, address: Optional[int] = None, count: Optional[int] = None, **kwargs
    ):
        if _debug:
            ReadBitsRequestBase._debug("__init__ %r %r %r", address, count, kwargs)

        MPDU.__init__(self, **kwargs)
        self.address = address
        self.count = count

    def encode(self) -> PDU:
        if _debug:
            ReadBitsRequestBase._debug("encode")
        assert self.address is not None
        assert self.count is not None

        # unit identifier, function code, two shorts
        self.mbapLength = 6

        pdu = MPDU.encode(self)
        pdu.put_short(self.address)
        pdu.put_short(self.count)
        if _debug:
            MPDU._debug("    - pdu: %r", pdu)
        pdu.debug_contents()

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MPDU:  # type: ignore[override]
        if _debug:
            ReadBitsRequestBase._debug("decode %r", pdu)

        mpdu = class_()
        mpdu.functionCode = pdu.get()
        mpdu.address = pdu.get_short()
        mpdu.count = pdu.get_short()

        return mpdu


@modpypes_debugging
class ReadBitsResponseBase(MPDU, DebugContents):

    """
    Base class for messages that are responses to reading bit values.
    This is inherited by both :class:`ReadCoilsResponse` and
    :class:`ReadDiscreteInputsResponse`.
    """

    _debug_contents = ("count", "bits")

    def __init__(
        self, count: Optional[int] = None, values: Optional[List[int]] = None, **kwargs
    ):
        if _debug:
            ReadBitsResponseBase._debug("__init__ %r %r %r", count, values, kwargs)

        MPDU.__init__(self, **kwargs)
        if values is not None:
            self.bits = values
        else:
            self.bits = []

        bit_count = len(self.bits)
        octet_count = (bit_count // 8) + (1 if bit_count % 8 != 0 else 0)

        if count is not None:
            assert count == octet_count
        else:
            count = octet_count
        self.count = count

    def encode(self) -> PDU:
        if _debug:
            ReadBitsResponseBase._debug("encode")
        assert isinstance(self.bits, list)

        stringbits = _packBitsToString(self.bits)
        if _debug:
            ReadBitsResponseBase._debug("    - stringbits: %r", stringbits)
        self.count = len(stringbits)

        # unit identifier, function code, count, packed bits
        self.mbapLength = 3 + len(stringbits)

        pdu = MPDU.encode(self)
        pdu.put(self.count)
        pdu.put_data(stringbits)

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MPDU:  # type: ignore[override]
        if _debug:
            ReadBitsResponseBase._debug("decode %r", pdu)

        mpdu = class_()
        mpdu.functionCode = pdu.get()
        mpdu.count = pdu.get()
        mpdu.bits = _unpackBitsFromString(pdu.get_data(mpdu.count))

        return mpdu


@modpypes_debugging
class ReadRegistersRequestBase(MPDU, DebugContents):

    """
    Base class for messages requesting register values.
    This is inherited by both :class:`ReadMultipleRegistersRequest` and
    :class:`ReadInputRegistersRequest`.
    """

    _debug_contents = ("address", "count")

    def __init__(
        self, address: Optional[int] = None, count: Optional[int] = None, **kwargs
    ):
        if _debug:
            ReadRegistersRequestBase._debug("__init__ %r %r %r", address, count, kwargs)

        MPDU.__init__(self, **kwargs)
        self.address = address
        self.count = count

    def encode(self) -> PDU:
        if _debug:
            ReadRegistersRequestBase._debug("encode")
        assert isinstance(self.address, int)
        assert isinstance(self.count, int)
        assert (self.count >= 1) and (self.count <= 125)

        # unit identifier, function code, two shorts
        self.mbapLength = 6

        pdu = MPDU.encode(self)
        pdu.put_short(self.address)
        pdu.put_short(self.count)

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MPDU:  # type: ignore[override]
        if _debug:
            ReadRegistersRequestBase._debug("decode %r", pdu)

        mpdu = class_()
        mpdu.functionCode = pdu.get()
        mpdu.address = pdu.get_short()
        mpdu.count = pdu.get_short()

        return mpdu


@modpypes_debugging
class ReadRegistersResponseBase(MPDU, DebugContents):

    """
    Base class for messages requesting register values.
    This is inherited by both :class:`ReadMultipleRegistersResponse` and
    :class:`ReadInputRegistersResponse`.
    """

    _debug_contents = (
        "count",
        "registers",
    )

    def __init__(
        self,
        count: Optional[int] = None,
        registers: Optional[List[int]] = None,
        **kwargs,
    ):
        if _debug:
            ReadRegistersResponseBase._debug(
                "__init__ %r %r %r", count, registers, kwargs
            )

        MPDU.__init__(self, **kwargs)
        if registers is not None:
            self.registers = registers
        else:
            self.registers = []

        if count is not None:
            assert count == len(self.registers) * 2
        else:
            count = len(self.registers) * 2
        self.count = count

    def encode(self) -> PDU:
        if _debug:
            ReadRegistersResponseBase._debug("encode")
        assert isinstance(self.count, int)
        assert isinstance(self.registers, list)

        # unit identifier, function code, register byte count, registers
        self.count = len(self.registers) * 2
        self.mbapLength = 3 + self.count

        pdu = MPDU.encode(self)
        pdu.put(self.count)
        for reg in self.registers:
            pdu.put_short(reg)

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MPDU:  # type: ignore[override]
        if _debug:
            ReadRegistersResponseBase._debug("decode %r", pdu)

        mpdu = class_()
        mpdu.functionCode = pdu.get()
        mpdu.count = pdu.get()

        mpdu.registers = []
        for i in range(mpdu.count // 2):
            mpdu.registers.append(pdu.get_short())

        return mpdu


@modpypes_debugging
class ReadWriteValueBase(MPDU, DebugContents):

    """
    Base class for messages reading and writing values.  This class is
    inherted by :class:`WriteSingleCoilRequest`, :class:`WriteSingleCoilResponse`,
    :class:`WriteSingleRegisterRequest`,  and :class:`WriteSingleRegisterResponse`.
    """

    _debug_contents = ("address", "value")

    def __init__(
        self, address: Optional[int] = None, value: Optional[int] = None, **kwargs
    ):
        if _debug:
            ReadWriteValueBase._debug("__init__ %r %r %r", address, value, kwargs)

        MPDU.__init__(self, **kwargs)
        self.address = address
        self.value = value

    def encode(self) -> PDU:
        if _debug:
            ReadWriteValueBase._debug("encode")
        assert self.address is not None
        assert self.value is not None

        # unit identifier, function code, two shorts
        self.mbapLength = 6

        pdu = MPDU.encode(self)
        pdu.put_short(self.address)
        pdu.put_short(self.value)

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MPDU:  # type: ignore[override]
        if _debug:
            ReadWriteValueBase._debug("decode %r", pdu)

        mpdu = class_()
        mpdu.functionCode = pdu.get()
        mpdu.address = pdu.get_short()
        mpdu.value = pdu.get_short()

        return mpdu


# ------------------------------

#
#   Read Coils
#


@modpypes_debugging
@register_request_type
class ReadCoilsRequest(ReadBitsRequestBase):

    """
    Read Coils Request
    """

    functionCode = MPDU.readCoils

    def __init__(self, address=None, count=None, **kwargs):
        if _debug:
            ReadCoilsRequest._debug("__init__ %r %r %r", address, count, kwargs)

        ReadBitsRequestBase.__init__(
            self, address, count, function_code=ReadCoilsRequest.functionCode, **kwargs
        )


@modpypes_debugging
@register_response_type
class ReadCoilsResponse(ReadBitsResponseBase):

    """
    Read Coils Response
    """

    functionCode = MPDU.readCoils

    def __init__(self, count=None, values=None, **kwargs):
        if _debug:
            ReadCoilsResponse._debug("__init__ %r %r", values, kwargs)

        ReadBitsResponseBase.__init__(
            self,
            count=count,
            values=values,
            function_code=ReadCoilsResponse.functionCode,
            **kwargs,
        )


#
#   Read Descrete Inputs
#


@modpypes_debugging
@register_request_type
class ReadDiscreteInputsRequest(ReadBitsRequestBase):

    """
    Read Discrete Inputs Request
    """

    functionCode = MPDU.readDiscreteInputs

    def __init__(self, address=None, count=None, **kwargs):
        if _debug:
            ReadDiscreteInputsRequest._debug(
                "__init__ %r %r %r", address, count, kwargs
            )

        ReadBitsRequestBase.__init__(
            self,
            address,
            count,
            function_code=ReadDiscreteInputsRequest.functionCode,
            **kwargs,
        )


@modpypes_debugging
@register_response_type
class ReadDiscreteInputsResponse(ReadBitsResponseBase):

    """
    Read Discrete Inputs Response
    """

    functionCode = MPDU.readDiscreteInputs

    def __init__(self, count=None, values=None, **kwargs):
        if _debug:
            ReadDiscreteInputsResponse._debug("__init__ %r %r", values, kwargs)

        ReadBitsResponseBase.__init__(
            self,
            count,
            values,
            function_code=ReadDiscreteInputsResponse.functionCode,
            **kwargs,
        )


#
#   Read Holding Registers
#


@modpypes_debugging
@register_request_type
class ReadHoldingRegistersRequest(ReadRegistersRequestBase):

    """
    Read Holding Registers Request
    """

    functionCode = MPDU.readHoldingRegisters

    def __init__(self, address=None, count=None, **kwargs):
        if _debug:
            ReadHoldingRegistersRequest._debug(
                "__init__ %r %r %r", address, count, kwargs
            )

        ReadRegistersRequestBase.__init__(
            self,
            address,
            count,
            function_code=ReadHoldingRegistersRequest.functionCode,
            **kwargs,
        )


@modpypes_debugging
@register_response_type
class ReadHoldingRegistersResponse(ReadRegistersResponseBase):

    """
    Read Holding Registers Response
    """

    functionCode = MPDU.readHoldingRegisters

    def __init__(self, values=None, **kwargs):
        if _debug:
            ReadHoldingRegistersResponse._debug("__init__ %r %r", values, kwargs)

        ReadRegistersResponseBase.__init__(
            self,
            values,
            function_code=ReadHoldingRegistersResponse.functionCode,
            **kwargs,
        )


#
#   Read Input Registers
#


@modpypes_debugging
@register_request_type
class ReadInputRegistersRequest(ReadRegistersRequestBase):

    """
    Read Input Registers Request
    """

    functionCode = MPDU.readInputRegisters

    def __init__(self, address=None, count=None, **kwargs):
        if _debug:
            ReadInputRegistersRequest._debug(
                "__init__ %r %r %r", address, count, kwargs
            )

        ReadRegistersRequestBase.__init__(
            self,
            address,
            count,
            function_code=ReadInputRegistersRequest.functionCode,
            **kwargs,
        )


@modpypes_debugging
@register_response_type
class ReadInputRegistersResponse(ReadRegistersResponseBase):

    """
    Read Input Registers Response
    """

    functionCode = MPDU.readInputRegisters

    def __init__(self, count=None, values=None, **kwargs):
        if _debug:
            ReadInputRegistersResponse._debug(
                "__init__ %r %r %r", count, values, kwargs
            )

        ReadRegistersResponseBase.__init__(
            self,
            count,
            values,
            function_code=ReadInputRegistersResponse.functionCode,
            **kwargs,
        )


#
#   Write Single Coil
#


@modpypes_debugging
@register_request_type
class WriteSingleCoilRequest(ReadWriteValueBase):

    """
    Write Single Coil Request
    """

    functionCode = MPDU.writeSingleCoil

    def __init__(self, address=None, value=None, **kwargs):
        if _debug:
            WriteSingleCoilRequest._debug("__init__ %r %r %r", address, value, kwargs)

        ReadWriteValueBase.__init__(
            self,
            address,
            value,
            function_code=WriteSingleCoilRequest.functionCode,
            **kwargs,
        )


@modpypes_debugging
@register_response_type
class WriteSingleCoilResponse(ReadWriteValueBase):

    """
    Write Single Coil Response
    """

    functionCode = MPDU.writeSingleCoil

    def __init__(self, address=None, value=None, **kwargs):
        if _debug:
            WriteSingleCoilResponse._debug("__init__ %r %r %r", address, value, kwargs)

        ReadWriteValueBase.__init__(
            self,
            address,
            value,
            function_code=WriteSingleCoilResponse.functionCode,
            **kwargs,
        )


#
#   Write Single Register
#


@modpypes_debugging
@register_request_type
class WriteSingleRegisterRequest(ReadWriteValueBase):

    """
    Write Single Register Request
    """

    functionCode = MPDU.writeSingleRegister

    def __init__(self, address=None, value=None, **kwargs):
        if _debug:
            WriteSingleRegisterRequest._debug(
                "__init__ %r %r %r", address, value, kwargs
            )

        ReadWriteValueBase.__init__(
            self,
            address,
            value,
            function_code=WriteSingleRegisterRequest.functionCode,
            **kwargs,
        )


@modpypes_debugging
@register_response_type
class WriteSingleRegisterResponse(ReadWriteValueBase):

    """
    Write Single Register Response
    """

    functionCode = MPDU.writeSingleRegister

    def __init__(self, address=None, value=None, **kwargs):
        if _debug:
            WriteSingleRegisterResponse._debug(
                "__init__ %r %r %r", address, value, kwargs
            )

        ReadWriteValueBase.__init__(
            self,
            address,
            value,
            function_code=WriteSingleRegisterResponse.functionCode,
            **kwargs,
        )


#
#   Write Multiple Coils
#


@modpypes_debugging
@register_request_type
class WriteMultipleCoilsRequest(MPDU, DebugContents):

    """
    Write Multiple Coils Request
    """

    _debug_contents = ("address", "count", "coils")

    functionCode = MPDU.writeMultipleCoils

    def __init__(self, address=None, count=None, coils=None, **kwargs):
        if _debug:
            WriteMultipleCoilsRequest._debug(
                "__init__ %r %r %r %r", address, count, coils, kwargs
            )
        raise NotImplementedError("needs help")

        MPDU.__init__(
            self, function_code=WriteMultipleCoilsRequest.functionCode, **kwargs
        )
        self.address = address
        self.count = count
        if coils is not None:
            self.coils = coils
        else:
            self.coils = [False] * count

    def encode(self, pdu):
        if _debug:
            WriteMultipleCoilsRequest._debug("encode %r", pdu)

        MPDU.encode(self, pdu)
        pdu.put_short(self.address)
        pdu.put_short(self.count)

        stringbits = _packBitsToString(self.coils)
        pdu.put(len(stringbits))
        pdu.put_data(stringbits)
        pdu.mbapLength = len(pdu.pduData) + 2

    def decode(self, pdu):
        if _debug:
            WriteMultipleCoilsRequest._debug("decode %r", pdu)

        MPDU.decode(self, pdu)

        self.address = pdu.get_short()
        self.count = pdu.get_short()

        datalen = pdu.get()
        coils = _unpackBitsFromString(pdu.get_data(datalen))
        self.coils = coils[: self.count]


@modpypes_debugging
@register_response_type
class WriteMultipleCoilsResponse(MPDU, DebugContents):

    """
    Write Multiple Coils Response
    """

    _debug_contents = ("address", "count")

    functionCode = MPDU.writeMultipleCoils

    def __init__(self, address=None, count=None, **kwargs):
        if _debug:
            WriteMultipleCoilsResponse._debug(
                "__init__ %r %r %r", address, count, kwargs
            )
        raise NotImplementedError("needs help")

        MPDU.__init__(
            self, function_code=WriteMultipleCoilsResponse.functionCode, **kwargs
        )
        self.address = address
        self.count = count

    def encode(self, pdu):
        if _debug:
            WriteMultipleCoilsResponse._debug("encode %r", pdu)

        MPDU.encode(self, pdu)
        pdu.put_short(self.address)
        pdu.put_short(self.count)
        pdu.mbapLength = len(pdu.pduData) + 2

    def decode(self, pdu):
        if _debug:
            WriteMultipleCoilsResponse._debug("decode %r", pdu)

        MPDU.decode(self, pdu)

        self.address = pdu.get_short()
        self.count = pdu.get_short()


#
#   Write Multiple Registers
#


@modpypes_debugging
@register_request_type
class WriteMultipleRegistersRequest(MPDU, DebugContents):

    """
    Write Multiple Registers Request
    """

    _debug_contents = ("address", "count", "registers")

    functionCode = MPDU.writeMultipleRegisters

    def __init__(self, address=None, count=None, registers=None, **kwargs):
        if _debug:
            WriteMultipleRegistersRequest._debug(
                "__init__ %r %r %r %r", address, count, registers, kwargs
            )
        raise NotImplementedError("needs help")

        MPDU.__init__(
            self, function_code=WriteMultipleRegistersRequest.functionCode, **kwargs
        )
        self.address = address
        self.count = count
        if registers is not None:
            self.registers = registers
        elif count is not None:
            self.registers = [0] * self.count
        else:
            self.registers = None

    def encode(self, pdu):
        if _debug:
            WriteMultipleRegistersRequest._debug("encode %r", pdu)

        MPDU.encode(self, pdu)
        pdu.put_short(self.address)
        pdu.put_short(self.count)

        pdu.put(len(self.registers) * 2)
        for reg in self.registers:
            pdu.put_short(reg)
        pdu.mbapLength = len(pdu.pduData) + 2

    def decode(self, pdu):
        if _debug:
            WriteMultipleRegistersRequest._debug("decode %r", pdu)

        MPDU.decode(self, pdu)

        self.address = pdu.get_short()
        self.count = pdu.get_short()

        datalen = pdu.get()
        self.registers = []
        for i in range(datalen // 2):
            self.registers.append(pdu.get_short())


@modpypes_debugging
@register_response_type
class WriteMultipleRegistersResponse(MPDU, DebugContents):

    """
    Write Multiple Registers Response
    """

    _debug_contents = ("address", "count")

    functionCode = MPDU.writeMultipleRegisters

    def __init__(self, address=None, count=None, **kwargs):
        if _debug:
            WriteMultipleRegistersResponse._debug(
                "__init__ %r %r %r", address, count, kwargs
            )
        raise NotImplementedError("needs help")

        MPDU.__init__(
            self, function_code=WriteMultipleRegistersResponse.functionCode, **kwargs
        )
        self.address = address
        self.count = count

    def encode(self, pdu):
        if _debug:
            WriteMultipleRegistersResponse._debug("encode %r", pdu)

        MPDU.encode(self, pdu)
        pdu.put_short(self.address)
        pdu.put_short(self.count)
        pdu.mbapLength = len(pdu.pduData) + 2

    def decode(self, pdu):
        if _debug:
            WriteMultipleRegistersResponse._debug("decode %r", pdu)

        MPDU.decode(self, pdu)

        self.address = pdu.get_short()
        self.count = pdu.get_short()


#
#   Read Write Multiple Registers
#


@modpypes_debugging
@register_request_type
class ReadWriteMultipleRegistersRequest(MPDU, DebugContents):

    """
    Read Write Multiple Registers Request
    """

    _debug_contents = ("raddress", "rcount", "waddress", "wcount", "registers")

    functionCode = MPDU.readWriteMultipleRegisters

    def __init__(
        self,
        raddress=None,
        rcount=None,
        waddress=None,
        wcount=None,
        registers=None,
        **kwargs,
    ):
        if _debug:
            ReadWriteMultipleRegistersRequest._debug(
                "__init__ %r %r %r %r %r %r",
                raddress,
                rcount,
                waddress,
                wcount,
                registers,
                kwargs,
            )
        raise NotImplementedError("needs help")

        MPDU.__init__(
            self, function_code=ReadWriteMultipleRegistersRequest.functionCode, **kwargs
        )
        self.raddress = raddress
        self.rcount = rcount
        self.waddress = waddress
        self.wcount = wcount
        if registers is not None:
            self.registers = registers
        else:
            self.registers = [0] * wcount

    def encode(self, pdu):
        if _debug:
            ReadWriteMultipleRegistersRequest._debug("encode %r", pdu)

        MPDU.encode(self, pdu)
        pdu.put_short(self.raddress)
        pdu.put_short(self.rcount)
        pdu.put_short(self.waddress)
        pdu.put_short(self.wcount)

        pdu.put(len(self.registers) * 2)
        for reg in self.registers:
            pdu.put_short(reg)
        pdu.mbapLength = len(pdu.pduData) + 2

    def decode(self, pdu):
        if _debug:
            ReadWriteMultipleRegistersRequest._debug("decode %r", pdu)

        MPDU.decode(self, pdu)
        self.raddress = pdu.get_short()
        self.rcount = pdu.get_short()
        self.waddress = pdu.get_short()
        self.wcount = pdu.get_short()

        datalen = pdu.get()
        self.registers = []
        for i in range(datalen // 2):
            self.registers.append(pdu.get_short())


@modpypes_debugging
@register_response_type
class ReadWriteMultipleRegistersResponse(MPDU, DebugContents):

    """
    Read Write Multiple Registers Response
    """

    _debug_contents = ("registers",)

    functionCode = MPDU.readWriteMultipleRegisters

    def __init__(self, registers=None, **kwargs):
        if _debug:
            ReadWriteMultipleRegistersResponse._debug(
                "__init__ %r %r", registers, kwargs
            )
        raise NotImplementedError("needs help")

        MPDU.__init__(
            self,
            function_code=ReadWriteMultipleRegistersResponse.functionCode,
            **kwargs,
        )
        if registers is not None:
            self.registers = registers
        else:
            self.registers = []

    def encode(self, pdu):
        if _debug:
            ReadWriteMultipleRegistersResponse._debug("encode %r", pdu)

        MPDU.encode(self, pdu)
        pdu.put(len(self.registers) * 2)
        for reg in self.registers:
            pdu.put_short(reg)
        pdu.mbapLength = len(pdu.pduData) + 2

    def decode(self, pdu):
        if _debug:
            ReadWriteMultipleRegistersResponse._debug("decode %r", pdu)

        MPDU.decode(self, pdu)
        datalen = pdu.get()
        self.registers = []
        for i in range(datalen // 2):
            self.registers.append(pdu.get_short())


#
#   Exception Response
#


@modpypes_debugging
class ExceptionResponse(MPDU, DebugContents):

    """
    Exception Response
    """

    _debug_contents = ("exceptionCode",)
    exceptionCode: int

    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    ILLEGAL_RESPONSE_LENGTH = 0x04
    ACKNOWLEDGE = 0x05
    SLAVE_DEVICE_BUSY = 0x06
    NEGATIVE_ACKNOWLEDGE = 0x07
    MEMORY_PARITY_ERROR = 0x08
    GATEWAY_PATH_UNAVAILABLE = 0x0A
    GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 0x0B

    def __init__(self, function: int, exceptionCode: int, **kwargs):
        if _debug:
            ExceptionResponse._debug(
                "__init__ %r %r %r", function, exceptionCode, kwargs
            )

        MPDU.__init__(self, function_code=function + 128, **kwargs)
        self.exceptionCode = exceptionCode

    def encode(self) -> PDU:
        if _debug:
            ExceptionResponse._debug("encode")
        assert isinstance(self.exceptionCode, int)

        # unit identifier, function code, exception code
        self.mbapLength = 3

        pdu = MPDU.encode(self)
        pdu.put(self.exceptionCode)
        if _debug:
            MPDU._debug("    - pdu: %r", pdu)

        return pdu

    @classmethod
    def decode(class_, pdu: PDU) -> MPDU:  # type: ignore[override]
        if _debug:
            ReadBitsRequestBase._debug("decode %r", pdu)

        function_code = pdu.get()
        exception_code = pdu.get()

        return class_(function_code, exception_code)
