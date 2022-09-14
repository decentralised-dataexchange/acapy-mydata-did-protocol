from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    DATA_AGREEMENT_TERMINATION_TERMINATE,
    PROTOCOL_PACKAGE,
)
from mydata_did.v1_0.models.data_agreement_termination_terminate_model import (
    DataAgreementTerminationTerminateBody,
    DataAgreementTerminationTerminateBodySchema,
)
from mydata_did.v1_0.utils.regex import MYDATA_DID

# Handler class for data agreement terminate message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_termination_terminate_handler.DataAgreementTerminationTerminateMessageHandler"
)


class DataAgreementTerminationTerminateMessage(AgentMessage):
    """
    Message class for data agreement termination terminate message.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = DATA_AGREEMENT_TERMINATION_TERMINATE

        # Message schema class
        schema_class = "DataAgreementTerminationTerminateMessageSchema"

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        body: DataAgreementTerminationTerminateBody,
        **kwargs,
    ):
        """
        Initialize a DataAgreementTerminationTerminateMessage message instance.
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


class DataAgreementTerminationTerminateMessageSchema(AgentMessageSchema):
    """
    Schema class for data agreement termination terminate message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataAgreementTerminationTerminateMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(DataAgreementTerminationTerminateBodySchema, required=True)
