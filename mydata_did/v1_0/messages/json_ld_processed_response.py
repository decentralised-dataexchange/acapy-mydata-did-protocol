from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    JSON_LD_PROCESSED_RESPONSE_DATA,
    PROTOCOL_PACKAGE,
)
from mydata_did.v1_0.models.json_ld_processed_response_model import (
    JSONLDProcessedResponseBody,
    JSONLDProcessedResponseBodySchema,
)

# Handler class for JSONLD processed response message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".json_ld_processed_response_handler.JSONLDProcessedResponseHandler"
)


class JSONLDProcessedResponseMessage(AgentMessage):
    """
    Message class for JSONLD processed response message.
    """

    class Meta:

        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = JSON_LD_PROCESSED_RESPONSE_DATA

        # Message schema class
        schema_class = "JSONLDProcessedResponseMessageSchema"

    def __init__(
        self,
        *,
        body: JSONLDProcessedResponseBody,
        **kwargs,
    ):
        """
        Initialize a JSONLDProcessedResponseMessage message instance.
        """
        super().__init__(**kwargs)

        # Message body
        self.body = body


class JSONLDProcessedResponseMessageSchema(AgentMessageSchema):
    """
    Schema class for JSONLD processed response message
    """

    class Meta:
        # The message class that this schema is for
        model_class = JSONLDProcessedResponseMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # Message body
    body = fields.Nested(JSONLDProcessedResponseBodySchema, required=True)
