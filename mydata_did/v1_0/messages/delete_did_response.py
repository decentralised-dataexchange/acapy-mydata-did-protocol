from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema

from marshmallow import EXCLUDE, fields

from ..message_types import PROTOCOL_PACKAGE, DELETE_DID_RESPONSE
from ..utils.regex import MYDATA_DID

# Handler class for /mydata/v1.0/delete-did-response
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".delete_did_response_handler.DeleteDIDResponseHandler"
)


class DeleteDIDResponseMessageBody(BaseModel):
    """
    Delete DID Response Message body class
    """
    class Meta:

        # Schema class
        schema_class = "DeleteDIDResponseMessageBodySchema"
    
    def __init__(self, *, status: str, did: str, **kwargs):
        """
        Initialize delete DID response message body
        """
        super().__init__(**kwargs)

        # Set attributes
        self.status = status
        self.did = did

class DeleteDIDResponseMessageBodySchema(BaseModelSchema):
    """
    Delete DID Response Message body schema
    """
    class Meta:
        # Model class
        model_class = DeleteDIDResponseMessageBody

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE
    
    # Status
    status = fields.Str(data_key="status")

    # Deleted DID
    did = fields.Str(data_key="did", **MYDATA_DID)

class DeleteDIDResponseMessage(AgentMessage):
    """
    Message class for delete-did-response
    """

    class Meta:

        # Handler class that should handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = DELETE_DID_RESPONSE

        # Message schema class
        schema_class = "DeleteDIDResponseMessageSchema"

    def __init__(self, *, from_did, to_did, created_time, body: DeleteDIDResponseMessageBody, **kwargs):
        """
        Initialize a delete-did-response message instance
        """

        super().__init__(**kwargs)

        # Set attributes
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class DeleteDIDResponseMessageSchema(AgentMessageSchema):
    """
    Schema class for delete-did-response
    """
    class Meta:

        # Model class
        model_class = DeleteDIDResponseMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE
    
    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created Time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(DeleteDIDResponseMessageBodySchema, required=True)
