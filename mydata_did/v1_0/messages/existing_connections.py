from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import EXISTING_CONNECTIONS, PROTOCOL_PACKAGE
from mydata_did.v1_0.models.existing_connections_model import (
    ExistingConnectionsBody,
    ExistingConnectionsBodySchema,
)

# Handler class for existing connections message.
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".existing_connections_handler.ExistingConnectionsMessageHandler"
)


class ExistingConnectionsMessage(AgentMessage):
    """
    Message class for existing connections.
    """

    class Meta:

        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = EXISTING_CONNECTIONS

        # Message schema class
        schema_class = "ExistingConnectionsMessageSchema"

    def __init__(self, *, body: ExistingConnectionsBody, **kwargs):
        """
        Initialize a ExistingConnectionsMessage message instance.
        """
        super().__init__(**kwargs)

        # Message body
        self.body = body


class ExistingConnectionsMessageSchema(AgentMessageSchema):
    """
    Schema class for existing connections message.
    """

    class Meta:
        # The message class that this schema is for
        model_class = ExistingConnectionsMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # Message body
    body = fields.Nested(ExistingConnectionsBodySchema, required=True)
