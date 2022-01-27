from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import DATA_AGREEMENT_QR_CODE_WORKFLOW_INITIATE, PROTOCOL_PACKAGE
from ..models.data_agreement_qr_code_initiate_model import DataAgreementQrCodeInitiateBody, DataAgreementQrCodeInitiateBodySchema
from ..utils.regex import MYDATA_DID

# Handler class for data-agreement-qr-code/1.0/initiate message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_qr_code_initiate_handler.DataAgreementQrCodeInitiateHandler"
)

class DataAgreementQrCodeInitiateMessage(AgentMessage):
    """
    Message class for data agreement Qr code workflow initiate
    """

    class Meta:

        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = DATA_AGREEMENT_QR_CODE_WORKFLOW_INITIATE

        # Message schema class
        schema_class = "DataAgreementQrCodeInitiateMessageSchema"

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        body: DataAgreementQrCodeInitiateBody,
        **kwargs
    ):
        """
        Initialize a DataAgreementQrCodeInitiateMessage message instance.
        """
        super().__init__(**kwargs)

        # Sender DID
        self.from_did = from_did

        # Recipient DID
        self.to_did = to_did

        # The time the message was created
        self.created_time = created_time

        # Message body
        self.body = body


class DataAgreementQrCodeInitiateMessageSchema(AgentMessageSchema):
    """
    Schema class for data agreement qr code initiate message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataAgreementQrCodeInitiateMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(
        DataAgreementQrCodeInitiateBodySchema, 
        required=True
    )
