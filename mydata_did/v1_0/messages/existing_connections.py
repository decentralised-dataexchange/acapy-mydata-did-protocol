from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import EXISTING_CONNECTIONS, PROTOCOL_PACKAGE
from ..models.existing_connections_model import ExistingConnectionsBody, ExistingConnectionsBodySchema
from ..utils.regex import MYDATA_DID

# Handler class for connections/1.0/exists message
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

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        body: ExistingConnectionsBody,
        **kwargs
    ):
        """
        Initialize a ExistingConnectionsMessage message instance.
        """
        super().__init__(**kwargs)

        # Sender DID
        self.from_did = from_did

        # Recipient DID
        self.to_did = to_did

        # The time the message was created
        self.created_time = created_time

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

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(
        ExistingConnectionsBodySchema, 
        required=True
    )
