"""
Command Shell
"""

import asyncio

from typing import Any, Dict, Callable, Optional, Tuple, Type

from modpypes3.debugging import modpypes_debugging, ModuleLogger
from modpypes3.argparse import SimpleArgumentParser
from modpypes3.console import Console
from modpypes3.cmd import Cmd

from modpypes3.pdu import Address, UnitIPv4Address
from modpypes3.comm import bind
from modpypes3.mpdu import ExceptionResponse, DataType, data_types
from modpypes3.ipv4.tcp import TCPServerDirector
from modpypes3.app import ClientApplication, ServerCodec, ServerApplication


# some debugging
_debug = 0
_log = ModuleLogger(globals())

# testing register map
register_map: Dict[int, Tuple[str, Any]] = {
    44001: ("be-udint", 7750216),  # PowerScout3 kWh_System
    44003: ("uint", 64),  # PowerScout3 kW_System
    44013: ("uint", 72),  # PowerScout3 kVA_System
}


@modpypes_debugging
class CmdShell(Cmd):
    """
    Simple example that reads MODBUS registers
    """

    _debug: Callable[..., None]

    async def do_read(
        self,
        address: Address,
        register: int,
        dtype: str = "int",
    ) -> None:
        """
        usage: read address register [ dtype | n ]
        """
        if _debug:
            CmdShell._debug("do_read %r %r %r", address, register, dtype)
        global app

        # check the address
        if not isinstance(address, UnitIPv4Address):
            raise TypeError("UnitIPv4Address expected")

        # five or six digit register
        if 40000 <= register <= 49999:
            register -= 40000
        elif 400000 <= register <= 499999:
            register -= 400000
        else:
            raise ValueError("holding register address required: 4xxxx")

        datatype: Optional[Type[DataType]] = None

        # maybe a register count
        if dtype.isdigit():
            register_length = int(dtype)
        else:
            # look up the datatype
            datatype = data_types.get(dtype, None)
            if not datatype:
                raise ValueError("unknown data type")
            if _debug:
                CmdShell._debug("    - datatype: %r", datatype)
            register_length = datatype.registerLength
        if _debug:
            CmdShell._debug("    - register_length: %r", register_length)

        async with ClientApplication(address.addrTuple) as client:
            result = await client.read_holding_registers(
                unit_id=address.addrUnit,
                address=register - 1,
                count=register_length,
            )
            if _debug:
                CmdShell._debug("    - result: %r", result)

            if isinstance(result, ExceptionResponse):
                response = "Exception: " + str(result.exceptionCode)
            elif datatype:
                response = str(datatype.unpack(result))
            else:
                response = str(result)

            await self.response(str(response))


async def main() -> None:
    try:
        parser = SimpleArgumentParser(prog="modpypes3")
        parser.add_argument(
            "-c",
            "--client",
            action="store_true",
            default=None,
            help="client (default)",
        )
        parser.add_argument(
            "-s",
            "--server",
            action="store_true",
            default=None,
            help="server",
        )
        args = parser.parse_args()
        if _debug:
            _log.debug("args: %r", args)

        if args.server:
            if _debug:
                _log.debug("server")

            # build a samll stack
            director = TCPServerDirector(Address(args.address or "0.0.0.0:10502"))
            codec = ServerCodec()
            app = ServerApplication(args.unit, register_map)
            bind(director, codec, app)

            # wait forever
            await director.serve_forever()

        else:
            # build a very small stack
            console = Console()
            cmd = CmdShell()
            bind(console, cmd)

            # wait until the user is done
            await console.fini.wait()

    except KeyboardInterrupt:
        if _debug:
            _log.debug("keyboard interrupt")


if __name__ == "__main__":
    asyncio.run(main())
