"""
PDU
"""

from __future__ import annotations

import sys
import re
import socket
import struct
import ipaddress

from copy import copy as _copy
from typing import Union, Any, List, TextIO, Tuple, Dict, Optional, Callable, cast

try:
    import netifaces  # type: ignore[import]
except ImportError:
    netifaces = None

from .debugging import ModuleLogger, DebugContents, modpypes_debugging, btox, xtob
from .errors import DecodingError

# pack/unpack constants
_short_mask = 0xFFFF
_long_mask = 0xFFFFFFFF

# some debugging
_debug = 0
_log = ModuleLogger(globals())

#
#   Address
#

_unit_identifier = r"(\d+)"
unit_identifier_re = re.compile("^" + _unit_identifier + "$")

_ipv4_address_port = r"(\d+\.\d+\.\d+\.\d+)(?::(\d+))?"
_unit_ipv4_address_port = r"(\d+)[@]" + _ipv4_address_port
ipv4_address_port_re = re.compile("^" + _ipv4_address_port + "$")
unit_ipv4_address_port_re = re.compile("^" + _unit_ipv4_address_port + "$")

_ipv6_address = r"([.:0-9A-Fa-f]+(?:/\d+)?)"
_ipv6_address_port = r"(?:\[)([.:0-9A-Fa-f]+(?:/\d+)?)(?:\])(?::(\d+))?"
_unit_ipv6_address_port = r"(\d+)[@]" + _ipv6_address_port
ipv6_address_re = re.compile("^" + _ipv6_address + "$")
ipv6_address_port_re = re.compile("^" + _ipv6_address_port + "$")
unit_ipv6_address_port_re = re.compile("^" + _unit_ipv6_address_port + "$")

_ipv6_interface = r"(?:(?:[%])([\w]+))?"
_ipv6_address_interface = _ipv6_address + _ipv6_interface
_ipv6_address_port_interface = _ipv6_address_port + _ipv6_interface
ipv6_address_interface_re = re.compile("^" + _ipv6_address_interface + "$")
ipv6_address_port_interface_re = re.compile("^" + _ipv6_address_port_interface + "$")

combined_pattern = re.compile(
    "^(?:"
    + _unit_identifier
    + "|"
    + _ipv4_address_port
    + "|"
    + _unit_ipv4_address_port
    + "|"
    + _ipv6_address_port
    + "|"
    + _unit_ipv6_address_port
    + ")$"
)

interface_port_re = re.compile(r"^(?:([\w]+))(?::(\d+))?$")

network_types: Dict[str, type]


@modpypes_debugging
class AddressMetaclass(type):
    """
    Amazing documentation here.
    """

    _debug: Callable[..., None]

    def __new__(
        cls: Any,
        clsname: str,
        superclasses: Tuple[type, ...],
        attributedict: Dict[str, Any],
    ) -> "AddressMetaclass":
        if _debug:
            AddressMetaclass._debug(
                "__new__ %r %r %r", clsname, superclasses, attributedict
            )

        return cast(
            AddressMetaclass, type.__new__(cls, clsname, superclasses, attributedict)
        )

    def __call__(cls, *args: Any, **kwargs: Any) -> Address:
        if _debug:
            AddressMetaclass._debug("__call__ %r %r %r", cls, args, kwargs)

        # already subclassed, nothing to see here
        if cls is not Address:
            return cast(Address, type.__call__(cls, *args, **kwargs))

        network_type = kwargs.get("network_type", None)

        # network type was provided
        if network_type:
            if network_type not in network_types:
                raise ValueError("invalid network type")

            return super(AddressMetaclass, network_types[network_type]).__call__(*args, **kwargs)  # type: ignore[misc, no-any-return]

        if not args:
            if _debug:
                AddressMetaclass._debug("    - null")
            return super(AddressMetaclass, NullAddress).__call__(*args, **kwargs)  # type: ignore[misc, no-any-return]

        # match the address
        addr = args[0]

        if isinstance(addr, int):
            if _debug:
                AddressMetaclass._debug("    - int")
            if addr < 0:
                raise ValueError("invalid address")
            if addr <= 255:
                return super(AddressMetaclass, SerialAddress).__call__(addr, **kwargs)  # type: ignore[misc, no-any-return]

            raise ValueError("invalid address")

        if isinstance(addr, (bytes, bytearray)):
            raise NotImplementedError("needs help")

            if _debug:
                AddressMetaclass._debug("    - bytes or bytearray")
            if isinstance(addr, bytearray):
                addr_bytes = bytes(addr)
            else:
                addr_bytes = addr

            if len(addr_bytes) <= 0:
                raise ValueError("invalid address")

            if len(addr_bytes) == 1:
                return super(AddressMetaclass, SerialAddress).__call__(addr_bytes, **kwargs)  # type: ignore[misc, no-any-return]
            if len(addr_bytes) == 6:
                return super(AddressMetaclass, IPv4Address).__call__(addr_bytes, **kwargs)  # type: ignore[misc, no-any-return]
            if len(addr_bytes) == 18:
                return super(AddressMetaclass, IPv6Address).__call__(addr_bytes, **kwargs)  # type: ignore[misc, no-any-return]

            raise ValueError("invalid address")

        if isinstance(addr, str):
            if _debug:
                AddressMetaclass._debug("    - str")

            m = combined_pattern.match(addr)
            if m:
                if _debug:
                    Address._debug("    - combined pattern: %r", m.groups())

                (
                    unit_id,
                    ipv4_addr,
                    ipv4_port,
                    unit_ipv4_unit,
                    unit_ipv4_addr,
                    unit_ipv4_port,
                    ipv6_addr,
                    ipv6_port,
                    unit_ipv6_unit,
                    unit_ipv6_addr,
                    unit_ipv6_port,
                ) = m.groups()

                if unit_id:
                    if _debug:
                        AddressMetaclass._debug("    - simple address")

                    unit_identifier = int(unit_id)
                    if unit_identifier >= 256:
                        raise ValueError("unit number out of range")

                    address = super(AddressMetaclass, SerialAddress).__call__(unit_identifier, **kwargs)  # type: ignore[misc]

                if ipv4_addr:
                    if _debug:
                        Address._debug("    - IPv4 address")
                    if not ipv4_port:
                        ipv4_port = "502"

                    address = super(AddressMetaclass, IPv4Address).__call__(ipv4_addr, port=int(ipv4_port), **kwargs)  # type: ignore[misc]

                if unit_ipv4_unit:
                    if _debug:
                        Address._debug("    - unit IPv4 address")

                    unit_identifier = int(unit_ipv4_unit)
                    if unit_identifier >= 256:
                        raise ValueError("unit number out of range")

                    if not unit_ipv4_port:
                        unit_ipv4_port = "502"

                    address = super(AddressMetaclass, UnitIPv4Address).__call__(unit_identifier, unit_ipv4_addr, port=int(unit_ipv4_port), **kwargs)  # type: ignore[misc]

                if ipv6_addr:
                    if _debug:
                        Address._debug("    - IPv6 address")
                    if not ipv6_port:
                        ipv6_port = "502"

                    address = super(AddressMetaclass, IPv6Address).__call__(ipv6_addr, port=int(ipv6_port), **kwargs)  # type: ignore[misc]

                if unit_ipv6_unit:
                    if _debug:
                        Address._debug("    - unit IPv6 address")

                    unit_identifier = int(unit_ipv6_unit)
                    if unit_identifier >= 256:
                        raise ValueError("unit number out of range")

                    if not unit_ipv6_port:
                        unit_ipv6_port = "502"

                    address = super(AddressMetaclass, UnitIPv6Address).__call__(unit_identifier, unit_ipv6_addr, port=int(unit_ipv6_port), **kwargs)  # type: ignore[misc]

                return address  # type: ignore[no-any-return]

            if interface_port_re.match(addr):
                return super(AddressMetaclass, IPv4Address).__call__(*args, **kwargs)  # type: ignore[misc, no-any-return]

            raise ValueError("unrecognized format")

        if isinstance(addr, tuple):
            if _debug:
                AddressMetaclass._debug("    - tuple")
            addr, port = addr

            try:
                test_address = ipaddress.ip_address(addr)
                if _debug:
                    AddressMetaclass._debug("    - test_address: %r", test_address)

                if isinstance(test_address, ipaddress.IPv4Address):
                    if _debug:
                        AddressMetaclass._debug("    - ipv4")
                    return super(AddressMetaclass, IPv4Address).__call__(addr, port=port, **kwargs)  # type: ignore[misc, no-any-return]
                elif isinstance(test_address, ipaddress.IPv6Address):
                    if _debug:
                        AddressMetaclass._debug("    - ipv6")
                    return super(AddressMetaclass, IPv6Address).__call__(addr, port=port, **kwargs)  # type: ignore[misc, no-any-return]
            except Exception as err:
                if _debug:
                    AddressMetaclass._debug("    - err: %r", err)

        if isinstance(addr, ipaddress.IPv4Address):
            if _debug:
                AddressMetaclass._debug("    - ipv4")
            return super(AddressMetaclass, IPv4Address).__call__(addr, **kwargs)  # type: ignore[misc, no-any-return]

        if isinstance(addr, ipaddress.IPv6Address):
            if _debug:
                AddressMetaclass._debug("    - ipv6")
            return super(AddressMetaclass, IPv6Address).__call__(addr, **kwargs)  # type: ignore[misc, no-any-return]

        raise ValueError("invalid address")


#
#   Address
#


@modpypes_debugging
class Address(metaclass=AddressMetaclass):
    """
    Amazing documentation here.
    """

    _debug: Callable[..., None]
    _warning: Callable[..., None]

    addrNetworkType: Optional[str]
    addrUnit: Optional[int]
    addrTuple: Optional[Tuple[Any, ...]]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if _debug:
            Address._debug("__init__ %r %r", args, kwargs)
        raise NotImplementedError

    def __str__(self) -> str:
        return "?"

    def __repr__(self) -> str:
        return "<%s %s>" % (self.__class__.__name__, self.__str__())

    def __hash__(self) -> int:
        return hash((self.addrUnit, self.addrTuple))

    def __eq__(self, arg: object) -> bool:
        # try an coerce it into an address
        if not isinstance(arg, Address):
            arg = Address(arg)

        # basic components must match
        rslt = (self.addrUnit == arg.addrUnit) and (self.addrTuple == arg.addrTuple)

        return rslt

    def __ne__(self, arg: object) -> bool:
        return not self.__eq__(arg)

    #    def __lt__(self, arg: 'Address') -> bool:
    #        return self._tuple() < arg._tuple()

    def dict_contents(
        self,
        use_dict: Optional[Dict[str, Any]] = None,
        as_class: Union[Callable[[], Dict[str, Any]]] = dict,
    ) -> Dict[str, Any]:
        """Return the contents of an object as a dict."""
        if _debug:
            _log.debug("dict_contents use_dict=%r as_class=%r", use_dict, as_class)

        # make/extend the dictionary of content
        if use_dict is None:
            use_dict = as_class()

        # save the string version of the address
        use_dict.__setitem__("str", str(self))

        # return what we built/updated
        return use_dict


#
#   NullAddress
#


@modpypes_debugging
class NullAddress(Address):
    """
    Amazing documentation here.
    """

    def __init__(self, network_type: str = "null") -> None:
        if _debug:
            NullAddress._debug("NullAddress.__init__ network_type=%r", network_type)

        if network_type != "null":
            raise ValueError("network type must be 'null'")

        self.addrUnit = None
        self.addrTuple = ()

    def __str__(self) -> str:
        return "Null"


#
#   SerialAddress
#


@modpypes_debugging
class SerialAddress(Address):
    """
    Amazing documentation here.
    """

    def __init__(
        self,
        addr: Union[int, bytes, bytearray, str],
        network_type: str = "serial",
    ) -> None:
        if _debug:
            SerialAddress._debug("__init__ %r network_type=%r", addr, network_type)

        if network_type != "serial":
            raise ValueError("network type must be 'serial'")

        self.addrNetworkType = "serial"

        if _debug:
            SerialAddress._debug("    - %r", type(addr))

        if isinstance(addr, int):
            if _debug:
                SerialAddress._debug("    - int")
            self.addrUnit = addr

        elif isinstance(addr, (bytes, bytearray)):
            if _debug:
                SerialAddress._debug("    - bytes, bytearray")
            self.addrUnit = addr[0]

        elif isinstance(addr, str):
            self.addrUnit = int(addr)

        else:
            raise ValueError("invalid address")

        self.addrTuple = ()

    def __str__(self) -> str:
        return str(self.addrUnit)


#
#   IPv4Address
#


@modpypes_debugging
class IPv4Address(Address, ipaddress.IPv4Interface):  # type: ignore[misc]
    """
    Amazing documentation here.
    """

    addrPort: int
    addrTuple: Tuple[str, int]

    def __init__(
        self,
        addr: Union[
            int,
            str,
            bytes,
            bytearray,
            Tuple[Union[str, int], int],
            ipaddress.IPv4Address,
        ],
        port: int = 502,
        network_type: str = "ipv4",
    ) -> None:
        if _debug:
            IPv4Address._debug("__init__ %r network_type=%r", addr, network_type)
        if _debug:
            IPv4Address._debug("    - type(addr): %r", type(addr))

        if network_type != "ipv4":
            raise ValueError("network type must be 'ipv4'")

        self.addrUnit = None
        self.addrNetworkType = "ipv4"

        if isinstance(addr, int):
            if _debug:
                IPv4Address._debug("    - int")
            ipaddress.IPv4Interface.__init__(self, addr)

        elif isinstance(addr, str):
            if _debug:
                IPv4Address._debug("    - str")

            while True:
                ipv4_match = ipv4_address_port_re.match(addr)
                if ipv4_match:
                    addr, _port = ipv4_match.groups()
                    if _debug:
                        IPv4Address._debug(
                            "    - addr, _mask, _port: %r, %r", addr, _port
                        )
                    ipaddress.IPv4Interface.__init__(self, addr)

                    if _port:
                        port = int(_port)
                    break

                interface_port_match = interface_port_re.match(addr)
                if interface_port_match:
                    interface, _port = interface_port_match.groups()
                    if _debug:
                        IPv4Address._debug(
                            "    - interface, _port: %r, %r", interface, _port
                        )

                    if interface == "host":
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        try:
                            # doesn't even have to be reachable
                            s.connect(("10.255.255.255", 1))
                            ipv4_address = s.getsockname()[0]

                            ipaddress.IPv4Interface.__init__(self, ipv4_address)
                            if _port:
                                port = int(_port)
                            break
                        except Exception:
                            raise ValueError("no IPv4 address for host interface")
                        finally:
                            s.close()

                    if not netifaces:
                        raise RuntimeError(
                            "install netifaces for interface name addresses"
                        )

                    ifaddresses = netifaces.ifaddresses(interface)
                    ipv4_addresses = ifaddresses.get(netifaces.AF_INET, None)
                    if not ipv4_addresses:
                        raise ValueError(
                            "no IPv4 address for interface: %r" % (interface,)
                        )
                    if len(ipv4_addresses) > 1:
                        raise ValueError(
                            "multiple IPv4 addresses for interface: %r" % (interface,)
                        )

                    ipv4_address = ipv4_addresses[0]
                    if _debug:
                        IPv4Address._debug("    - ipv4_address: %r", ipv4_address)

                    ipaddress.IPv4Interface.__init__(
                        self, ipv4_address["addr"] + "/" + ipv4_address["netmask"]
                    )

                    if _port:
                        port = int(_port)
                    break

                raise ValueError("invalid address")

        elif isinstance(addr, (bytes, bytearray)):
            if _debug:
                IPv4Address._debug("    - bytes: %r..%r", addr[:4], addr[4:6])
            if len(addr) != 6:
                raise ValueError("IPv4 requires 6 bytes")
            ipaddress.IPv4Interface.__init__(self, bytes(addr[:4]))

            # extract the port
            port = struct.unpack("!H", addr[4:6])[0]

        elif isinstance(addr, tuple):
            if _debug:
                IPv4Address._debug("    - tuple")
            addr, port = addr

            if isinstance(addr, int):
                ipaddress.IPv4Interface.__init__(self, addr)
            elif isinstance(addr, str):
                ipaddress.IPv4Interface.__init__(self, addr)

        elif isinstance(addr, ipaddress.IPv4Address):
            ipaddress.IPv4Interface.__init__(self, addr)

        else:
            raise ValueError("invalid address")

        self.addrPort = port
        self.addrTuple = (self.ip.compressed, port)

    def __str__(self) -> str:
        suffix = ":" + str(self.addrPort) if (self.addrPort != 502) else ""
        return self.ip.compressed + suffix


#
#   UnitIPv4Address
#


@modpypes_debugging
class UnitIPv4Address(IPv4Address):  # type: ignore[misc]
    """
    Amazing documentation here.
    """

    def __init__(
        self,
        unit_identifier: int,
        addr: Union[
            int,
            str,
            bytes,
            bytearray,
            Tuple[Union[str, int], int],
            ipaddress.IPv4Address,
        ],
        port: int = 502,
        network_type: str = "ipv4",
    ) -> None:
        if _debug:
            UnitIPv4Address._debug("__init__ %r network_type=%r", addr, network_type)
        IPv4Address.__init__(self, addr, port, network_type)
        self.addrUnit = unit_identifier

    def __str__(self) -> str:
        suffix = ":" + str(self.addrPort) if (self.addrPort != 502) else ""
        return str(self.addrUnit) + "@" + self.ip.compressed + suffix


#
#   IPv6Address
#


@modpypes_debugging
class IPv6Address(Address, ipaddress.IPv6Interface):  # type: ignore[misc]
    """
    Amazing documentation here.
    """

    addrPort: int
    addrTuple: Tuple[str, int, int, int]

    def __init__(
        self,
        addr: Union[
            int,
            str,
            bytes,
            bytearray,
            Tuple[Union[str, int], int],
            ipaddress.IPv6Address,
        ],
        port: int = 502,
        interface: Union[None, int, str] = None,
        network_type: str = "ipv6",
    ) -> None:
        if _debug:
            IPv6Address._debug("__init__ %r network_type=%r", addr, network_type)

        if network_type != "ipv6":
            raise ValueError("network type must be 'ipv6'")

        self.addrUnit = None
        self.addrNetworkType = "ipv6"

        if interface is None:
            interface_index = 0
        elif isinstance(interface, int):
            interface_index = interface
        elif isinstance(interface, str):
            interface_index = socket.if_nametoindex(interface)
        else:
            raise ValueError("invalid interface")
        if _debug:
            IPv6Address._debug("    - interface_index: %r", interface_index)

        if isinstance(addr, int):
            if _debug:
                IPv6Address._debug("    - int")
            ipaddress.IPv6Interface.__init__(self, addr)

        elif isinstance(addr, str):
            if _debug:
                IPv6Address._debug("    - str")

            while True:
                # matching the "raw" format like fe80::67a9/64%eno1
                ipv6_match = ipv6_address_interface_re.match(addr)
                if ipv6_match:
                    addr, _interface = ipv6_match.groups()
                    if _debug:
                        IPv6Address._debug(
                            "    - addr, _interface: %r, %r", addr, _interface
                        )

                    if (_interface and interface is not None) and (
                        _interface != interface
                    ):
                        raise ValueError("interface mismatch")
                        interface = _interface

                    if _interface:
                        interface_index = socket.if_nametoindex(_interface)
                        if _debug:
                            IPv6Address._debug(
                                "    - interface_index: %r", interface_index
                            )

                    ipaddress.IPv6Interface.__init__(self, addr)
                    break

                # matching the extended format with optional port
                # [fe80::67a9/64]:47809%eno1
                ipv6_match = ipv6_address_port_interface_re.match(addr)
                if ipv6_match:
                    addr, _port, _interface = ipv6_match.groups()
                    if _debug:
                        IPv6Address._debug(
                            "    - addr, _port, _interface: %r, %r, %r",
                            addr,
                            _port,
                            _interface,
                        )

                    if (_interface and interface is not None) and (
                        _interface != interface
                    ):
                        raise ValueError("interface mismatch")
                        interface = _interface

                    if _interface:
                        interface_index = socket.if_nametoindex(_interface)
                        if _debug:
                            IPv6Address._debug(
                                "    - interface_index: %r", interface_index
                            )

                    ipaddress.IPv6Interface.__init__(self, addr)

                    if _port:
                        port = int(_port)
                    break

                # matching an interface name with an optional port eno1:47809
                interface_port_match = interface_port_re.match(addr)
                if interface_port_match:
                    if not netifaces:
                        raise RuntimeError(
                            "install netifaces for interface name addresses"
                        )

                    _interface, _port = interface_port_match.groups()
                    if _debug:
                        IPv6Address._debug(
                            "    - _interface, _port: %r, %r", _interface, _port
                        )

                    if (_interface and interface is not None) and (
                        _interface != interface
                    ):
                        raise ValueError("interface mismatch")
                        interface = _interface

                    if _port:
                        port = int(_port)

                    ifaddresses = netifaces.ifaddresses(_interface)
                    ipv6_addresses = ifaddresses.get(netifaces.AF_INET6, None)
                    if not ipv6_addresses:
                        ValueError("no IPv6 address for interface: %r" % (interface,))
                    if len(ipv6_addresses) > 1:
                        ValueError(
                            "multiple IPv6 addresses for interface: %r" % (interface,)
                        )

                    ipv6_address = ipv6_addresses[0]
                    if _debug:
                        IPv6Address._debug("    - ipv6_address: %r", ipv6_address)

                    # get the address
                    addr_str = ipv6_address["addr"]
                    if _debug:
                        IPv6Address._debug("    - addr_str: %r", addr_str)

                    # find the interface name (a.k.a. scope identifier)
                    if "%" in addr_str:
                        addr_str, _interface = addr_str.split("%")
                        if (interface is not None) and (_interface != interface):
                            raise ValueError("interface mismatch")

                        interface_index = socket.if_nametoindex(_interface)
                        if _debug:
                            IPv6Address._debug(
                                "    - interface_index: %r", interface_index
                            )

                    # if the prefix length is in the address, leave it, otherwise
                    # convert the netmask to a prefix length
                    if "/" not in addr_str:
                        netmask_bytes = xtob(ipv6_address["netmask"].replace(":", ""))
                        prefix_len = sum(bin(x).count("1") for x in netmask_bytes)
                        addr_str += "/" + str(prefix_len)

                    ipaddress.IPv6Interface.__init__(self, addr_str)
                    break

                # raw, perhaps compressed, address
                if re.match("^[.:0-9A-Fa-f]+$", addr):
                    if _debug:
                        IPv6Address._debug("    - just an address")
                    ipaddress.IPv6Interface.__init__(self, addr)
                    break

                raise ValueError("invalid address")

        elif isinstance(addr, (bytes, bytearray)):
            if _debug:
                IPv6Address._debug("    - bytes")
            if len(addr) != 18:
                raise ValueError("IPv6 requires 18 bytes")

            ipaddress.IPv6Interface.__init__(self, bytes(addr[:16]))

            # extract the port
            port = struct.unpack("!H", addr[16:18])[0]

        elif isinstance(addr, tuple):
            if _debug:
                IPv6Address._debug("    - tuple")
            addr, port = addr[:2]

            if isinstance(addr, (int, str)):
                ipaddress.IPv6Interface.__init__(self, addr)

        elif isinstance(addr, ipaddress.IPv6Address):
            ipaddress.IPv6Interface.__init__(self, addr)

        else:
            raise ValueError("invalid address")

        self.addrPort = port
        self.addrTuple = (self.ip.compressed, port, 0, interface_index)

    def __str__(self) -> str:
        suffix = str(self.addrPort) if (self.addrPort != 502) else ""
        return "[" + self.ip.compressed + "]" + suffix


#
#   UnitIPv6Address
#


@modpypes_debugging
class UnitIPv6Address(IPv6Address):  # type: ignore[misc]
    """
    Amazing documentation here.
    """

    def __init__(
        self,
        unit_identifier: int,
        addr: Union[
            int,
            str,
            bytes,
            bytearray,
            Tuple[Union[str, int], int],
            ipaddress.IPv6Address,
        ],
        port: int = 502,
        network_type: str = "ipv6",
    ) -> None:
        if _debug:
            UnitIPv6Address._debug(
                "__init__ %r %r network_type=%r", unit_identifier, addr, network_type
            )
        IPv6Address.__init__(
            self, addr, port, interface=None, network_type=network_type
        )
        self.addrUnit = unit_identifier

    def __str__(self) -> str:
        suffix = ":" + str(self.addrPort) if (self.addrPort != 502) else ""
        return str(self.addrUnit) + "@[" + self.ip.compressed + "]" + suffix


#
#   Network Types
#

network_types = {
    "null": NullAddress,  # not a standard type
    "serial": SerialAddress,
    "ipv4": IPv4Address,
    "ipv6": IPv6Address,
}


#
#   PCI
#


@modpypes_debugging
class PCI(DebugContents):
    """
    Amazing documentation here.
    """

    _debug: Callable[..., None]
    _debug_contents: Tuple[str, ...] = (
        "pduSource",
        "pduDestination",
        "pduUserData+",
    )

    pduSource: Optional[Any]
    pduDestination: Optional[Any]
    pduUserData: Optional[bytes]

    def __init__(
        self,
        *,
        source: Optional[Any] = None,
        destination: Optional[Any] = None,
        user_data: Optional[bytes] = None,
    ) -> None:
        if _debug:
            PCI._debug("__init__")

        # this call will fail if there are args or kwargs, but not if there
        # is another class in the __mro__ of this thing being constructed
        # super(PCI, self).__init__(*args, **kwargs)

        # save the values
        self.pduSource = source
        self.pduDestination = destination
        self.pduUserData = user_data

    def update(self, pci: PCI) -> None:
        """
        Copy the PCI fields.
        """
        if _debug:
            PCI._debug("update %r", pci)

        self.pduUserData = pci.pduUserData
        self.pduSource = pci.pduSource
        self.pduDestination = pci.pduDestination
        self.pduUserData = pci.pduUserData

    def pci_contents(
        self,
        use_dict: Optional[Dict[str, Any]] = None,
        as_class: Union[Callable[[], Dict[str, Any]]] = dict,
    ) -> Dict[str, Any]:
        """
        Return the PCI contents as a dictionary or some other kind of mapping class.
        """
        if _debug:
            PCI._debug("pci_contents use_dict=%r as_class=%r", use_dict, as_class)

        # make/extend the dictionary of content
        if use_dict is None:
            use_dict = as_class()

        # save the values
        for k, v in (
            ("source", self.pduSource),
            ("destination", self.pduDestination),
            ("user_data", self.pduUserData),
        ):
            if _debug:
                PCI._debug("    - %r: %r", k, v)
            if v is None:
                continue

            if hasattr(v, "dict_contents"):
                v = v.dict_contents(as_class=as_class)  # type: ignore[union-attr]
            use_dict.__setitem__(k, v)

        # return what we built/updated
        return use_dict

    def dict_contents(
        self,
        use_dict: Optional[Dict[str, Any]] = None,
        as_class: Union[Callable[[], Dict[str, Any]]] = dict,
    ) -> Dict[str, Any]:
        """
        Return the PCI contents as a dictionary or some other kind of mapping class.
        """
        if _debug:
            PCI._debug("dict_contents use_dict=%r as_class=%r", use_dict, as_class)

        return self.pci_contents(use_dict=use_dict, as_class=as_class)


#
#   PDUData
#


@modpypes_debugging
class PDUData:
    """
    Amazing documentation here.
    """

    _debug: Callable[..., None]

    pduData: bytearray

    def __init__(self, data: Union[bytes, bytearray, "PDUData", None] = None):
        if _debug:
            PDUData._debug("__init__ %r", data)

        # this call will fail if there are args or kwargs, but not if there
        # is another class in the __mro__ of this thing being constructed
        # super(PDUData, self).__init__(*args, **kwargs)

        # function acts like a copy constructor
        if data is None:
            self.pduData = bytearray()
        elif isinstance(data, (bytes, bytearray)):
            self.pduData = bytearray(data)
        elif isinstance(data, PDUData):
            self.pduData = _copy(data.pduData)
        else:
            raise TypeError("bytes or bytearray expected")

    def get(self) -> int:
        if len(self.pduData) == 0:
            raise DecodingError("no more packet data")

        octet = self.pduData[0]
        del self.pduData[0]

        return octet

    def get_data(self, dlen: int) -> bytearray:
        if len(self.pduData) < dlen:
            raise DecodingError("no more packet data")

        data = self.pduData[:dlen]
        del self.pduData[:dlen]

        return data

    def get_short(self) -> int:
        return struct.unpack(">H", self.get_data(2))[0]  # type: ignore[no-any-return]

    def get_long(self) -> int:
        return struct.unpack(">L", self.get_data(4))[0]  # type: ignore[no-any-return]

    def put(self, n: int) -> None:
        # pduData is a bytearray
        self.pduData += bytes([n])

    def put_data(self, data: Union[bytes, bytearray, List[int]]) -> None:
        if isinstance(data, bytes):
            pass
        elif isinstance(data, bytearray):
            pass
        elif isinstance(data, list):
            data = bytes(data)
        else:
            raise TypeError("data must be bytes, bytearray, or a list")

        # regular append works
        self.pduData += data

    def put_short(self, n: int) -> None:
        self.pduData += struct.pack(">H", n & _short_mask)

    def put_long(self, n: int) -> None:
        self.pduData += struct.pack(">L", n & _long_mask)

    def debug_contents(
        self,
        indent: int = 1,
        file: TextIO = sys.stderr,
        _ids: Optional[List[Any]] = None,
    ) -> None:
        if isinstance(self.pduData, bytearray):
            if len(self.pduData) > 20:
                hexed = btox(self.pduData[:20], ".") + "..."
            else:
                hexed = btox(self.pduData, ".")
            file.write("%spduData = x'%s'\n" % ("    " * indent, hexed))
        else:
            file.write("%spduData = %r\n" % ("    " * indent, self.pduData))

    def pdudata_contents(
        self,
        use_dict: Optional[Dict[str, Any]] = None,
        as_class: Union[Callable[[], Dict[str, Any]]] = dict,
    ) -> Dict[str, Any]:
        """
        Return the PCI contents as a dictionary or some other kind of mapping class.
        """
        if _debug:
            PDUData._debug(
                "pdudata_contents use_dict=%r as_class=%r", use_dict, as_class
            )

        # make/extend the dictionary of content
        if use_dict is None:
            use_dict = as_class()

        # add the data if it is not None
        v = self.pduData
        if v is not None:
            if isinstance(v, bytearray):
                use_dict.__setitem__("data", btox(v))
            elif hasattr(v, "dict_contents"):
                v = v.dict_contents(as_class=as_class)

        # return what we built/updated
        return use_dict

    def dict_contents(
        self,
        use_dict: Optional[Dict[str, Any]] = None,
        as_class: Union[Callable[[], Dict[str, Any]]] = dict,
    ) -> Dict[str, Any]:
        """
        Return the PCI contents as a dictionary or some other kind of mapping class.
        """
        if _debug:
            PDUData._debug("dict_contents use_dict=%r as_class=%r", use_dict, as_class)

        return self.pdudata_contents(use_dict=use_dict, as_class=as_class)


#
#   PDU
#


@modpypes_debugging
class PDU(PCI, PDUData):
    """
    Amazing documentation here.
    """

    _debug: Callable[..., None]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if _debug:
            PDU._debug("__init__ %r %r", args, kwargs)
        PCI.__init__(self, **kwargs)
        PDUData.__init__(self, *args)

    def __str__(self) -> str:
        return "<%s %s -> %s : %s>" % (
            self.__class__.__name__,
            self.pduSource,
            self.pduDestination,
            btox(self.pduData, "."),
        )

    def dict_contents(
        self,
        use_dict: Optional[Dict[str, Any]] = None,
        as_class: Union[Callable[[], Dict[str, Any]]] = dict,
    ) -> Dict[str, Any]:
        """
        Return the PCI contents as a dictionary or some other kind of mapping class.
        """
        if _debug:
            PDUData._debug("dict_contents use_dict=%r as_class=%r", use_dict, as_class)

        # make/extend the dictionary of content
        if use_dict is None:
            use_dict = as_class()

        # call into the two base classes
        self.pci_contents(use_dict=use_dict, as_class=as_class)
        self.pdudata_contents(use_dict=use_dict, as_class=as_class)

        # return what we built/updated
        return use_dict
