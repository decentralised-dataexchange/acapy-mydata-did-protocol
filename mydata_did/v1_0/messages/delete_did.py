from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema

from marshmallow import EXCLUDE, fields

from ..message_types import PROTOCOL_PACKAGE, DELETE_DID
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".delete_did_handler.DeleteDIDHandler"
)

class DeleteDIDBody(BaseModel):
    class Meta:
        schema_class = "DeleteDIDBodySchema"
    
    def __init__(self, *, did: str, **kwargs):
        super().__init__(**kwargs)
        self.did = did

class DeleteDIDBodySchema(BaseModelSchema):
    class Meta:
        model_class = DeleteDIDBody
        unknown = EXCLUDE
    
    did = fields.Str(data_key="did")

class DeleteDID(AgentMessage):

    class Meta:
        handler_class = HANDLER_CLASS
        message_type = DELETE_DID
        schema_class = "DeleteDIDSchema"

    def __init__(self, *, from_did, to_did, created_time, body: DeleteDIDBody, **kwargs):
        super().__init__(**kwargs)
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class DeleteDIDSchema(AgentMessageSchema):
    
    class Meta:
        model_class = DeleteDID
        unknown = EXCLUDE
        signed_fields = ("body",)
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
    body = fields.Nested(DeleteDIDBodySchema, required=True)
