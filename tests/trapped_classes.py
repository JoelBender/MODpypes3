#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Trapped State Machine Classes
-----------------------------
"""

from modpypes3.debugging import modpypes_debugging, ModuleLogger
from modpypes3.comm import (
    Client,
    Server,
)  # , ServiceAccessPoint, ApplicationServiceElement

from .state_machine import State, StateMachine

# some debugging
_debug = 0
_log = ModuleLogger(globals())


class ServiceAccessPoint:
    pass


class ApplicationServiceElement:
    pass


@modpypes_debugging
class Trapper:

    """
    This class provides a set of utility functions that keeps the
    latest copy of the pdu parameter in the before_send(), after_send(),
    before_receive(), after_receive() and unexpected_receive() calls.
    """

    def __init__(self, *args, **kwargs):
        if _debug:
            Trapper._debug("__init__ %r %r", args, kwargs)
        super().__init__(*args, **kwargs)

        # reset to initialize
        self.reset()

    def reset(self):
        if _debug:
            Trapper._debug("reset")

        # flush the copies
        self.before_send_pdu = None
        self.after_send_pdu = None
        self.before_receive_pdu = None
        self.after_receive_pdu = None
        self.unexpected_receive_pdu = None

        # continue
        super().reset()

    def before_send(self, pdu):
        """Called before each PDU about to be sent."""
        if _debug:
            Trapper._debug("before_send %r", pdu)

        # keep a copy
        self.before_send_pdu = pdu

        # continue
        super().before_send(pdu)

    def after_send(self, pdu):
        """Called after each PDU sent."""
        if _debug:
            Trapper._debug("after_send %r", pdu)

        # keep a copy
        self.after_send_pdu = pdu

        # continue
        super().after_send(pdu)

    def before_receive(self, pdu):
        """Called with each PDU received before matching."""
        if _debug:
            Trapper._debug("before_receive %r", pdu)

        # keep a copy
        self.before_receive_pdu = pdu

        # continue
        super().before_receive(pdu)

    def after_receive(self, pdu):
        """Called with PDU received after match."""
        if _debug:
            Trapper._debug("after_receive %r", pdu)

        # keep a copy
        self.after_receive_pdu = pdu

        # continue
        super().after_receive(pdu)


@modpypes_debugging
class TrappedState(Trapper, State):

    """
    This class is a simple wrapper around the State class that keeps the
    latest copy of the pdu parameter in the before_send(), after_send(),
    before_receive(), after_receive() and unexpected_receive() calls.
    """

    def unexpected_receive(self, pdu):
        """Called with PDU that did not match."""
        if _debug:
            TrappedState._debug("unexpected_receive %r", pdu)

        # keep a copy
        self.unexpected_receive_pdu = pdu

        # continue
        super().unexpected_receive(pdu)


@modpypes_debugging
class TrappedStateMachine(Trapper, StateMachine):

    """
    This class is a simple wrapper around the StateMachine class that keeps the
    latest copy of the pdu parameter in the before_send(), after_send(),
    before_receive(), after_receive() and unexpected_receive() calls.

    It also provides a send() function, so when the machine runs it doesn't
    throw an exception.
    """

    def __init__(self, **kwargs):
        """Initialize a trapped state machine."""
        if _debug:
            TrappedStateMachine._debug("__init__ %r", kwargs)

        # provide a default state subclass
        if "state_subclass" not in kwargs:
            kwargs["state_subclass"] = TrappedState

        # pass them all along
        super().__init__(**kwargs)

    async def send(self, pdu):
        """Called to send a PDU."""
        if _debug:
            TrappedStateMachine._debug("send %r", pdu)

        # keep a copy
        self.sent = pdu

    async def unexpected_receive(self, pdu):
        """Called with PDU that did not match."""
        if _debug:
            TrappedStateMachine._debug("unexpected_receive %r", pdu)

        # keep a copy
        self.unexpected_receive_pdu = pdu

        # continue
        await super().unexpected_receive(pdu)


@modpypes_debugging
class TrappedClient(Client):

    """
    TrappedClient
    ~~~~~~~~~~~~~

    An instance of this class sits at the top of a stack.
    """

    def __init__(self):
        if _debug:
            TrappedClient._debug("__init__")
        super().__init__()

        # clear out some references
        self.request_sent = None
        self.confirmation_received = None

    async def request(self, pdu):
        if _debug:
            TrappedClient._debug("request %r", pdu)

        # a reference for checking
        self.request_sent = pdu

        # continue with regular processing
        await super().request(pdu)

    async def confirmation(self, pdu):
        if _debug:
            TrappedClient._debug("confirmation %r", pdu)

        # a reference for checking
        self.confirmation_received = pdu


@modpypes_debugging
class TrappedServer(Server):

    """
    TrappedServer
    ~~~~~~~~~~~~~

    An instance of this class sits at the bottom of a stack.
    """

    def __init__(self):
        if _debug:
            TrappedServer._debug("__init__")
        super().__init__()

        # clear out some references
        self.indication_received = None
        self.response_sent = None

    async def indication(self, pdu):
        if _debug:
            TrappedServer._debug("indication %r", pdu)

        # a reference for checking
        self.indication_received = pdu

    async def response(self, pdu):
        if _debug:
            TrappedServer._debug("response %r", pdu)

        # a reference for checking
        self.response_sent = pdu

        # continue with processing
        await super().response(pdu)


@modpypes_debugging
class TrappedClientStateMachine(TrappedClient, TrappedStateMachine):

    """
    TrappedClientStateMachine
    ~~~~~~~~~~~~~~~~~~~~~~~~~
    """

    def __init__(self):
        if _debug:
            TrappedClientStateMachine._debug("__init__")
        super().__init__()

    async def send(self, pdu):
        if _debug:
            TrappedClientStateMachine._debug("send %r", pdu)
        await self.request(pdu)

    async def confirmation(self, pdu):
        if _debug:
            TrappedClientStateMachine._debug("confirmation %r", pdu)
        await self.receive(pdu)


@modpypes_debugging
class TrappedServerStateMachine(TrappedServer, TrappedStateMachine):

    """
    TrappedServerStateMachine
    ~~~~~~~~~~~~~~~~~~~~~~~~~
    """

    def __init__(self):
        if _debug:
            TrappedServerStateMachine._debug("__init__")
        super().__init__()

    async def send(self, pdu):
        if _debug:
            TrappedServerStateMachine._debug("send %r", pdu)
        await self.response(pdu)

    async def indication(self, pdu):
        if _debug:
            TrappedServerStateMachine._debug("indication %r", pdu)
        await self.receive(pdu)


@modpypes_debugging
class TrappedServiceAccessPoint(ServiceAccessPoint):

    """
    TrappedServiceAccessPoint
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Note that while this class inherits from ServiceAccessPoint, it doesn't
    provide any stubbed behavior for sap_indication() or sap_confirmation(),
    so if these functions are called it will still raise NotImplementedError.

    To provide these functions, write a ServiceAccessPoint derived class and
    stuff it in the inheritance sequence:

        class Snort(ServiceAccessPoint):
            def sap_indication(self, pdu):
                ...do something...
            def sap_confirmation(self, pdu):
                ...do something...

        class TrappedSnort(TrappedServiceAccessPoint, Snort): pass

    The Snort functions will be called after the PDU is trapped.
    """

    def __init__(self, sapID=None):
        if _debug:
            TrappedServiceAccessPoint._debug("__init__(%s)", sapID)
        super().__init__(sapID)

        # clear out client references
        self.sap_request_sent = None
        self.sap_confirmation_received = None

        # clear out server references
        self.sap_indication_received = None
        self.sap_response_sent = None

    def sap_request(self, pdu):
        if _debug:
            TrappedServiceAccessPoint._debug("sap_request(%s) %r", self.serviceID, pdu)

        # a reference for checking
        self.sap_request_sent = pdu

        # continue with regular processing
        super().sap_request(pdu)

    def sap_indication(self, pdu):
        if _debug:
            TrappedServiceAccessPoint._debug(
                "sap_indication(%s) %r", self.serviceID, pdu
            )

        # a reference for checking
        self.sap_indication_received = pdu

        # continue with regular processing
        super().sap_indication(pdu)

    def sap_response(self, pdu):
        if _debug:
            TrappedServiceAccessPoint._debug("sap_response(%s) %r", self.serviceID, pdu)

        # a reference for checking
        self.sap_response_sent = pdu

        # continue with processing
        super().sap_response(pdu)

    def sap_confirmation(self, pdu):
        if _debug:
            TrappedServiceAccessPoint._debug(
                "sap_confirmation(%s) %r", self.serviceID, pdu
            )

        # a reference for checking
        self.sap_confirmation_received = pdu

        # continue with regular processing
        super().sap_confirmation(pdu)


@modpypes_debugging
class TrappedApplicationServiceElement(ApplicationServiceElement):

    """
    TrappedApplicationServiceElement
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Note that while this class inherits from ApplicationServiceElement, it
    doesn't provide any stubbed behavior for indication() or confirmation(),
    so if these functions are called it will still raise NotImplementedError.

    To provide these functions, write a ServiceAccessPoint derived class and
    stuff it in the inheritance sequence:

        class Snort(ApplicationServiceElement):
            def indication(self, pdu):
                ...do something...
            def confirmation(self, pdu):
                ...do something...

        class TrappedSnort(TrappedApplicationServiceElement, Snort): pass

    The Snort functions will be called after the PDU is trapped.
    """

    def __init__(self, aseID=None):
        if _debug:
            TrappedApplicationServiceElement._debug("__init__(%s)", aseID)
        super().__init__(aseID)

        # clear out client references
        self.request_sent = None
        self.confirmation_received = None

        # clear out server references
        self.indication_received = None
        self.response_sent = None

    def request(self, pdu):
        if _debug:
            TrappedApplicationServiceElement._debug(
                "request(%s) %r", self.elementID, pdu
            )

        # a reference for checking
        self.request_sent = pdu

        # continue with regular processing
        super().request(pdu)

    def indication(self, pdu):
        if _debug:
            TrappedApplicationServiceElement._debug(
                "indication(%s) %r", self.elementID, pdu
            )

        # a reference for checking
        self.indication_received = pdu

        # continue with regular processing
        super().indication(pdu)

    def response(self, pdu):
        if _debug:
            TrappedApplicationServiceElement._debug(
                "response(%s) %r", self.elementID, pdu
            )

        # a reference for checking
        self.response_sent = pdu

        # continue with processing
        super().response(pdu)

    def confirmation(self, pdu):
        if _debug:
            TrappedServiceAccessPoint._debug("confirmation(%s) %r", self.elementID, pdu)

        # a reference for checking
        self.confirmation_received = pdu

        # continue with regular processing
        super().confirmation(pdu)
