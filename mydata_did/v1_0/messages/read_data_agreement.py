from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import READ_DATA_AGREEMENT, PROTOCOL_PACKAGE
from ..models.read_data_agreement_model import ReadDataAgreementBody, ReadDataAgreementBodySchema
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".read_data_agreement_handler.ReadDataAgreementHandler"
)

class ReadDataAgreement(AgentMessage):

    class Meta:
        handler_class = HANDLER_CLASS
        message_type = READ_DATA_AGREEMENT
        schema_class = "ReadDataAgreementSchema"

    def __init__(self, *, from_did, to_did, created_time, body: ReadDataAgreementBody, **kwargs):
        super().__init__(**kwargs)
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class ReadDataAgreementSchema(AgentMessageSchema):
    
    class Meta:
        model_class = ReadDataAgreement
        unknown = EXCLUDE
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
    body = fields.Nested(ReadDataAgreementBodySchema, required=True)
