from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import JSON_LD_PROCESSED_DATA, PROTOCOL_PACKAGE
from mydata_did.v1_0.models.json_ld_processed_model import (
    JSONLDProcessedBody,
    JSONLDProcessedBodySchema,
)

# Handler class for JSONLD processed message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers" ".json_ld_processed_handler.JSONLDProcessedHandler"
)


class JSONLDProcessedMessage(AgentMessage):
    """
    Message class for JSONLD processed message.
    """

    class Meta:

        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = JSON_LD_PROCESSED_DATA

        # Message schema class
        schema_class = "JSONLDProcessedMessageSchema"

    def __init__(self, *, body: JSONLDProcessedBody, **kwargs):
        """
        Initialize a JSONLDProcessedMessage message instance.
        """
        super().__init__(**kwargs)

        # Message body
        self.body = body


class JSONLDProcessedMessageSchema(AgentMessageSchema):
    """
    Schema class for JSONLD processed message
    """

    class Meta:
        # The message class that this schema is for
        model_class = JSONLDProcessedMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # Message body
    body = fields.Nested(JSONLDProcessedBodySchema, required=True)
