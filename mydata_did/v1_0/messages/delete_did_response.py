from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema

from marshmallow import EXCLUDE, fields

from ..message_types import PROTOCOL_PACKAGE, DELETE_DID_RESPONSE
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".delete_did_response_handler.DeleteDIDResponseHandler"
)


class DeleteDIDBodyResponse(BaseModel):
    class Meta:
        schema_class = "DeleteDIDBodyResponseSchema"
    
    def __init__(self, *, status: str, did: str, **kwargs):
        super().__init__(**kwargs)
        self.status = status
        self.did = did

class DeleteDIDBodyResponseSchema(BaseModelSchema):
    class Meta:
        model_class = DeleteDIDBodyResponse
        unknown = EXCLUDE
    
    status = fields.Str(data_key="status")
    did = fields.Str(data_key="did")

class DeleteDIDResponse(AgentMessage):

    class Meta:
        handler_class = HANDLER_CLASS
        message_type = DELETE_DID_RESPONSE
        schema_class = "DeleteDIDResponseSchema"

    def __init__(self, *, from_did, to_did, created_time, body: DeleteDIDBodyResponse, **kwargs):
        super().__init__(**kwargs)
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class DeleteDIDResponseSchema(AgentMessageSchema):
    
    class Meta:
        model_class = DeleteDIDResponse
        unknown = EXCLUDE
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
    body = fields.Nested(DeleteDIDBodyResponseSchema, required=True)
