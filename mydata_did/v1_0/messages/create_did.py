from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import CREATE_DID, PROTOCOL_PACKAGE
from ..models.diddoc_model import MyDataDIDDoc, MyDataDIDDocSchema
from ..utils.regex import MYDATA_DID

# Handler class for /mydata/v1.0/create-did
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".create_did_handler.CreateDIDHandler"
)

class CreateDIDMessage(AgentMessage):
    """
    Message class for creating a DID.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = CREATE_DID

        # Message schema class
        schema_class = "CreateDIDMessageSchema"

    def __init__(self, *, from_did, to_did, created_time, body: MyDataDIDDoc, **kwargs):
        """
        Initialize a CreateDIDMessage message instance.
        """
        super().__init__(**kwargs)

        # The DID of the agent that created the DID
        self.from_did = from_did

        # The DID of the agent that will receive the DID (MyData DID registry)
        self.to_did = to_did

        # The time the message was created
        self.created_time = created_time

        # The DIDDoc of the DID
        self.body = body

class CreateDIDMessageSchema(AgentMessageSchema):
    """
    Schema class for creating a DID.
    """
    
    class Meta:
        # The message class that this schema is for
        model_class = CreateDIDMessage
        
        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

        # Signed fields
        signed_fields = ("body",)

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(MyDataDIDDocSchema, required=True)
