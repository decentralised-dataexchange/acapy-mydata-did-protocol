from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import CREATE_DID, PROTOCOL_PACKAGE
from ..models.diddoc_model import MyDataDIDBody, MyDataDIDBodySchema
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".create_did_handler.CreateDIDHandler"
)

class CreateDID(AgentMessage):

    class Meta:
        handler_class = HANDLER_CLASS
        message_type = CREATE_DID
        schema_class = "CreateDIDSchema"

    def __init__(self, *, from_did, to_did, created_time, body: MyDataDIDBody, **kwargs):
        super().__init__(**kwargs)
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class CreateDIDSchema(AgentMessageSchema):
    
    class Meta:
        model_class = CreateDID
        unknown = EXCLUDE
        signed_fields = ("body",)
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
    body = fields.Nested(MyDataDIDBodySchema, required=True)
