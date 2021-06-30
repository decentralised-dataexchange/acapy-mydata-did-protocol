from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import CREATE_DID_RESPONSE, PROTOCOL_PACKAGE
from ..models.diddoc_model import MyDataDIDResponseBody, MyDataDIDResponseBodySchema
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".create_did_response_handler.CreateDIDResponseHandler"
)

class CreateDIDResponseMessage(AgentMessage):
    """
    Message class for create DID response.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = CREATE_DID_RESPONSE

        # Message schema class
        schema_class = "CreateDIDResponseMessageSchema"

    def __init__(self, *, from_did, to_did, created_time, body: MyDataDIDResponseBody, **kwargs):
        """
        Initialize a CreateDIDResponseMessage message instance.

        Args:
            from_did: Sender DID
            to_did: Recipient DID
            created_time: The time the message was created
            body: The DIDDoc of the DID
        """
        super().__init__(**kwargs)

        # Set attributes
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class CreateDIDResponseMessageSchema(AgentMessageSchema):
    """
    Schema class for create DID response.
    """
    
    class Meta:
        # The message class that this schema is for
        model_class = CreateDIDResponseMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE
    
    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(MyDataDIDResponseBodySchema, required=True)
