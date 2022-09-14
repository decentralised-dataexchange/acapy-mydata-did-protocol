from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    DATA_AGREEMENT_NEGOTIATION_RECEIPT,
    PROTOCOL_PACKAGE,
)
from mydata_did.v1_0.models.data_agreement_negotiation_receipt_model import (
    DataAgreementNegotiationReceiptBody,
    DataAgreementNegotiationReceiptBodySchema,
)

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".da_negotiation_receipt_handler.DataAgreementNegotiationReceiptMessageHandler"
)


class DataAgreementNegotiationReceiptMessage(AgentMessage):
    """
    Message class for data agreement negotiation receipt message.
    """

    class Meta:

        # Message type
        message_type = DATA_AGREEMENT_NEGOTIATION_RECEIPT

        # Schema class
        schema_class = "DataAgreementNegotiationReceiptMessageSchema"

        # Handler class
        handler_class = HANDLER_CLASS

    def __init__(self, *, body: DataAgreementNegotiationReceiptBody, **kwargs):
        """
        Initialize data agreement negotiation receipt message.
        """
        super().__init__(**kwargs)

        # Message body
        self.body = body


class DataAgreementNegotiationReceiptMessageSchema(AgentMessageSchema):
    """
    Schema class for data agreement negotiation accept message
    """

    class Meta:
        # Model class
        model_class = DataAgreementNegotiationReceiptMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # Message body
    body = fields.Nested(DataAgreementNegotiationReceiptBodySchema, required=True)
