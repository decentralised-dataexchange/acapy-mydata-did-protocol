from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import DATA_AGREEMENT_NEGOTIATION_REJECT, PROTOCOL_PACKAGE
from ..utils.regex import MYDATA_DID
from ..models.data_agreement_negotiation_reject_model import (
    DataAgreementNegotiationRejectBody,
    DataAgreementNegotiationRejectBodySchema
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

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        body: DataAgreementNegotiationRejectBody,
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


class DataAgreementNegotiationRejectMessageSchema(AgentMessageSchema):
    """
    Schema class for data agreement negotiation reject message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataAgreementNegotiationRejectMessage

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
        DataAgreementNegotiationRejectBodySchema, 
        required=True
    )
