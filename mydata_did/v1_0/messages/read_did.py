from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema

from marshmallow import EXCLUDE, fields

from ..message_types import PROTOCOL_PACKAGE, READ_DID
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".read_did_handler.ReadDIDHandler"
)

class ReadDIDBody(BaseModel):
    class Meta:
        schema_class = "ReadDIDBodySchema"
    
    def __init__(self, *, did: str, **kwargs):
        super().__init__(**kwargs)
        self.did = did

class ReadDIDBodySchema(BaseModelSchema):
    class Meta:
        model_class = ReadDIDBody
        unknown = EXCLUDE
    
    did = fields.Str(data_key="did")

class ReadDID(AgentMessage):

    class Meta:
        handler_class = HANDLER_CLASS
        message_type = READ_DID
        schema_class = "ReadDIDSchema"

    def __init__(self, *, from_did, to_did, created_time, body: ReadDIDBody, **kwargs):
        super().__init__(**kwargs)
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class ReadDIDSchema(AgentMessageSchema):
    
    class Meta:
        model_class = ReadDID
        unknown = EXCLUDE
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
    body = fields.Nested(ReadDIDBodySchema, required=True)
