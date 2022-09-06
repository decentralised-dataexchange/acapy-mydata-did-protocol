from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.config.provider import ClassProvider
from aries_cloudagent.core.protocol_registry import ProtocolRegistry
from aries_cloudagent.core.plugin_registry import PluginRegistry

from .v1_0.message_types import MESSAGE_TYPES
from .definition import versions
from .patched_protocols.issue_credential.v1_0.message_types import (
    MESSAGE_TYPES as ISSUE_CREDENTIAL_MESSAGE_TYPES,
)
from .patched_protocols.present_proof.v1_0.message_types import (
    MESSAGE_TYPES as PRESENT_PROOF_MESSAGE_TYPES,
)


async def setup(context: InjectionContext):
    # Register patched message types.
    protocol_registry: ProtocolRegistry = await context.inject(ProtocolRegistry)
    protocol_registry.register_message_types(
        MESSAGE_TYPES, version_definition=versions[0]
    )
    protocol_registry.register_message_types(
        ISSUE_CREDENTIAL_MESSAGE_TYPES, version_definition=versions[0]
    )
    protocol_registry.register_message_types(
        PRESENT_PROOF_MESSAGE_TYPES, version_definition=versions[0]
    )

    # Register patched protocol plugins
    plugin_registry: PluginRegistry = await context.inject(PluginRegistry)
    plugin_registry.register_plugin(
        "mydata_did.patched_protocols.issue_credential.v1_0"
    )
    plugin_registry.register_plugin("mydata_did.patched_protocols.present_proof.v1_0")

    # Unregister superseded protocols
    plugin_registry._plugins.pop("aries_cloudagent.protocols.issue_credential")
    plugin_registry._plugins.pop("aries_cloudagent.protocols.present_proof")
