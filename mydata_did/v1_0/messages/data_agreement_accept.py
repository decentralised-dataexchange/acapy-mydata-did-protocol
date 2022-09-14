from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from dexa_sdk.agreements.da.v1_0.models.da_instance_models import (
    DataAgreementInstanceModel,
    DataAgreementInstanceSchema,
)
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import DATA_AGREEMENT_NEGOTIATION_ACCEPT


class DataAgreementNegotiationAcceptMessage(AgentMessage):
    """
    Message class for data agreement negotiation accept message.
    """

    class Meta:

        # Message type
        message_type = DATA_AGREEMENT_NEGOTIATION_ACCEPT

        # Message schema class
        schema_class = "DataAgreementNegotiationAcceptMessageSchema"

    def __init__(self, *, body: DataAgreementInstanceModel, **kwargs):
        """
        Initialize a DataAgreementNegotiationAcceptMessage message instance.
        """
        super().__init__(**kwargs)

        # Message body
        self.body = body


class DataAgreementNegotiationAcceptMessageSchema(AgentMessageSchema):
    """
    Schema class for data agreement negotiation accept message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataAgreementNegotiationAcceptMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # Message body
    body = fields.Nested(DataAgreementInstanceSchema, required=True)
