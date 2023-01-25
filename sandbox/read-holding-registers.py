import asyncio

from modpypes3.debugging import ModuleLogger
from modpypes3.argparse import ArgumentParser

from modpypes3.pdu import Address
from modpypes3.mpdu import ExceptionResponse, data_types
from modpypes3.app import ClientApplication


# some debugging
_debug = 0
_log = ModuleLogger(globals())


async def main():
    try:
        client = None
        parser = ArgumentParser()
        parser.add_argument(
            "device_address",
            help="address of the device, n@1.2.3.4",
        )
        parser.add_argument(
            "register",
            type=int,
            help="register number",
        )
        parser.add_argument(
            "datatype",
            nargs="?",
            type=str,
            default="be-real",
            help="data type",
        )
        args = parser.parse_args()
        if _debug:
            _log.debug("args: %r", args)

        # interpret the address
        device_address = Address(args.device_address)
        if _debug:
            _log.debug("device_address: %r", device_address)

        # five or six digit register
        register = args.register
        if 40000 <= register <= 49999:
            register -= 40000
        elif 400000 <= register <= 499999:
            register -= 400000
        else:
            raise ValueError("holding register address required: 4xxxx")

        # look up the datatype
        datatype = data_types.get(args.datatype, None)
        if not datatype:
            raise ValueError("unknown data type")

        client = ClientApplication()

        result = await client.read_holding_registers(
            destination=device_address,
            address=register,
            count=datatype.registerLength,
        )
        if isinstance(result, ExceptionResponse):
            print("exception: ", result.exceptionCode)
        else:
            print(datatype.unpack(result))

    finally:
        if client:
            await client.director.close_connections()


asyncio.run(main())
