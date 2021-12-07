from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import DATA_AGREEMENT_NEGOTIATION_ACCEPT
from ..utils.regex import MYDATA_DID
from ..models.data_agreement_negotiation_accept_model import (
    DataAgreementNegotiationAcceptBody,
    DataAgreementNegotiationAcceptBodySchema
)


class DataAgreementNegotiationAcceptMessage(AgentMessage):
    """
    Message class for data agreement negotiation accept message.
    """

    class Meta:

        # Message type
        message_type = DATA_AGREEMENT_NEGOTIATION_ACCEPT

        # Message schema class
        schema_class = "DataAgreementNegotiationAcceptMessageSchema"

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        body: DataAgreementNegotiationAcceptBody,
        **kwargs
    ):
        """
        Initialize a DataAgreementNegotiationAcceptMessage message instance.
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


class DataAgreementNegotiationAcceptMessageSchema(AgentMessageSchema):
    """
    Schema class for data agreement negotiation accept message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataAgreementNegotiationAcceptMessage

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
        DataAgreementNegotiationAcceptBodySchema, 
        required=True
    )
