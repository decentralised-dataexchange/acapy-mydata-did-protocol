import os
import logging

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.config.provider import ClassProvider
from aries_cloudagent.core.protocol_registry import ProtocolRegistry

from .v1_0.message_types import MESSAGE_TYPES
from .dispatcher import Dispatcher
from .definition import versions


async def setup(context: InjectionContext):
    protocol_registry: ProtocolRegistry = await context.inject(ProtocolRegistry)
    protocol_registry.register_message_types(MESSAGE_TYPES, version_definition=versions[0])

    dispatcher = Dispatcher(context)
    context.injector.bind_instance(Dispatcher, dispatcher)