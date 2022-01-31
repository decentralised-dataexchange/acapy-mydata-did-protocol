from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import READ_ALL_DATA_AGREEMENT_TEMPLATE, PROTOCOL_PACKAGE
from ..utils.regex import MYDATA_DID

# Handler class for read all data agreement template message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".read_all_data_agreement_template_handler.ReadAllDataAgreementTemplateHandler"
)

class ReadAllDataAgreementTemplateMessage(AgentMessage):
    """
    Message class for read all data agreement template message.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = READ_ALL_DATA_AGREEMENT_TEMPLATE

        # Message schema class
        schema_class = "ReadAllDataAgreementTemplateMessageSchema"

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        **kwargs
    ):
        """
        Initialize a ReadAllDataAgreementTemplateMessage message instance.
        """
        super().__init__(**kwargs)

        # Sender DID
        self.from_did = from_did

        # Recipient DID
        self.to_did = to_did

        # The time the message was created
        self.created_time = created_time


class ReadAllDataAgreementTemplateMessageSchema(AgentMessageSchema):
    """
    Schema class for read all data agreement template message
    """

    class Meta:
        # The message class that this schema is for
        model_class = ReadAllDataAgreementTemplateMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")
