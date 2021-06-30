from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema

from marshmallow import EXCLUDE, fields

from ..message_types import PROTOCOL_PACKAGE, DELETE_DID
from ..utils.regex import MYDATA_DID

# Handler class for /mydata/v1.0/delete-did
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".delete_did_handler.DeleteDIDHandler"
)

class DeleteDIDMessageBody(BaseModel):
    """
    Message body class for deleting a DID.
    """
    class Meta:
        # Schema class
        schema_class = "DeleteDIDMessageBodySchema"
    
    def __init__(self, *, did: str, **kwargs):
        """
        Initialize delete DID message body.
        """
        super().__init__(**kwargs)

        # The DID to delete
        self.did = did

class DeleteDIDMessageBodySchema(BaseModelSchema):
    """
    Schema class for delete DID message body.
    """
    class Meta:
        # Message body class
        model_class = DeleteDIDMessageBody

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE
    
    # The DID to delete
    did = fields.Str(data_key="did", **MYDATA_DID)

class DeleteDIDMessage(AgentMessage):
    """
    Message class for deleting a DID.
    """

    class Meta:

        # Handler class that should handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = DELETE_DID

        # Message schema class
        schema_class = "DeleteDIDMessageSchema"

    def __init__(self, *, from_did, to_did, created_time, body: DeleteDIDMessageBody, **kwargs):
        """
        Initialize a DeleteDIDMessage instance
        """
        super().__init__(**kwargs)

        # Set attributes
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class DeleteDIDMessageSchema(AgentMessageSchema):
    """
    Schema for DeleteDIDMessage.
    """
    
    class Meta:
        # Model class
        model_class = DeleteDIDMessage

        # Unknown fields must be excluded.
        unknown = EXCLUDE

        # Signed fields
        signed_fields = ("body",)
    
    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created Time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(DeleteDIDMessageBodySchema, required=True)
