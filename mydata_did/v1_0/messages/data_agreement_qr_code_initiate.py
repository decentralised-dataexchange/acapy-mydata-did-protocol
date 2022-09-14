from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    DATA_AGREEMENT_QR_CODE_WORKFLOW_INITIATE,
    PROTOCOL_PACKAGE,
)
from mydata_did.v1_0.models.data_agreement_qr_code_initiate_model import (
    DataAgreementQrCodeInitiateBody,
    DataAgreementQrCodeInitiateBodySchema,
)

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

    def __init__(self, *, body: DataAgreementQrCodeInitiateBody, **kwargs):
        """
        Initialize a DataAgreementQrCodeInitiateMessage message instance.
        """
        super().__init__(**kwargs)

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

    # Message body
    body = fields.Nested(DataAgreementQrCodeInitiateBodySchema, required=True)
