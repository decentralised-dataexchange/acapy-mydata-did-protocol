from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import DATA_AGREEMENT_PROOFS_VERIFY, PROTOCOL_PACKAGE
from ..models.data_agreement_verify_model import DataAgreementVerifyBody, DataAgreementVerifyBodySchema
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_verify_handler.DataAgreementVerifyHandler"
)

class DataAgreementVerify(AgentMessage):

    class Meta:
        handler_class = HANDLER_CLASS
        message_type = DATA_AGREEMENT_PROOFS_VERIFY
        schema_class = "DataAgreementVerifySchema"

    def __init__(self, *, from_did, to_did, created_time, body: DataAgreementVerifyBody, **kwargs):
        super().__init__(**kwargs)
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body

class DataAgreementVerifySchema(AgentMessageSchema):
    
    class Meta:
        model_class = DataAgreementVerify
        unknown = EXCLUDE
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
    body = fields.Nested(DataAgreementVerifyBodySchema, required=True)
