from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    DATA_AGREEMENT_NEGOTIATION_REJECT,
    PROTOCOL_PACKAGE,
)
from mydata_did.v1_0.models.data_agreement_negotiation_reject_model import (
    DataAgreementNegotiationRejectBody,
    DataAgreementNegotiationRejectBodySchema,
)

# Handler class for data agreement reject message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_negotiation_reject_handler.DataAgreementNegotiationRejectMessageHandler"
)


class DataAgreementNegotiationRejectMessage(AgentMessage):
    """
    Message class for data agreement negotiation reject message.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = DATA_AGREEMENT_NEGOTIATION_REJECT

        # Message schema class
        schema_class = "DataAgreementNegotiationRejectMessageSchema"

    def __init__(self, *, body: DataAgreementNegotiationRejectBody, **kwargs):
        """
        Initialize a DataAgreementNegotiationAcceptMessage message instance.
        """
        super().__init__(**kwargs)

        # Message body
        self.body = body


class DataAgreementNegotiationRejectMessageSchema(AgentMessageSchema):
    """
    Schema class for data agreement negotiation reject message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataAgreementNegotiationRejectMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # Message body
    body = fields.Nested(DataAgreementNegotiationRejectBodySchema, required=True)
