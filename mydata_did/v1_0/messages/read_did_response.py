from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema

from marshmallow import EXCLUDE, fields

from ..message_types import PROTOCOL_PACKAGE, READ_DID_RESPONSE
from ..models.diddoc_model import MyDataDIDBodyResponse, MyDataDIDBodyResponseSchema
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".read_did_response_handler.ReadDIDResponseHandler"
)

class ReadDIDResponse(AgentMessage):

    class Meta:
        handler_class = HANDLER_CLASS
        message_type = READ_DID_RESPONSE
        schema_class = "ReadDIDResponseSchema"

    def __init__(self, *, from_did, to_did, created_time, body: MyDataDIDBodyResponse, **kwargs):
        super().__init__(**kwargs)
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class ReadDIDResponseSchema(AgentMessageSchema):
    
    class Meta:
        model_class = ReadDIDResponse
        unknown = EXCLUDE
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
    body = fields.Nested(MyDataDIDBodyResponseSchema, required=True)
