"""A credential ack message."""


from marshmallow import EXCLUDE

from aries_cloudagent.messaging.ack.message import Ack, AckSchema
from aries_cloudagent.messaging.decorators.base import BaseDecoratorSet

from ..message_types import CREDENTIAL_ACK, PROTOCOL_PACKAGE
from .....v1_0.decorators.patched_decorator_set import PatchedDecoratorSet

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.credential_ack_handler.CredentialAckHandler"
)


class CredentialAck(Ack):
    """Class representing a credential ack message."""

    class Meta:
        """Credential metadata."""

        handler_class = HANDLER_CLASS
        schema_class = "CredentialAckSchema"
        message_type = CREDENTIAL_ACK

    def __init__(self, **kwargs):
        """Initialize credential object."""
        super().__init__(_decorators=PatchedDecoratorSet(), **kwargs)


class CredentialAckSchema(AckSchema):
    """Credential ack schema."""

    class Meta:
        """Schema metadata."""

        model_class = CredentialAck
        unknown = EXCLUDE
