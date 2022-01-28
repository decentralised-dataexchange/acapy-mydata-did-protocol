from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import JSON_LD_PROCESSED_RESPONSE_DATA, PROTOCOL_PACKAGE
from ..models.json_ld_processed_response_model import JSONLDProcessedResponseBody, JSONLDProcessedResponseBodySchema
from ..utils.regex import MYDATA_DID

# Handler class for json-ld/1.0/processed-data-response message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".json_ld_processed_response_handler.JSONLDProcessedResponseHandler"
)


class JSONLDProcessedResponseMessage(AgentMessage):
    """
    Message class for json-ld/1.0/processed-data-response message.
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
        from_did,
        to_did,
        created_time,
        body: JSONLDProcessedResponseBody,
        **kwargs
    ):
        """
        Initialize a JSONLDProcessedResponseMessage message instance.
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


class JSONLDProcessedResponseMessageSchema(AgentMessageSchema):
    """
    Schema class for json-ld/1.0/processed-data-response message
    """

    class Meta:
        # The message class that this schema is for
        model_class = JSONLDProcessedResponseMessage

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
        JSONLDProcessedResponseBodySchema,
        required=True
    )
