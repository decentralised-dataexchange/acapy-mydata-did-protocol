import typing
from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import READ_ALL_DATA_AGREEMENT_TEMPLATE_RESPONSE, PROTOCOL_PACKAGE
from ..models.data_agreement_model import DataAgreementV1Schema, DataAgreementV1
from ..utils.regex import MYDATA_DID

# Handler class for read all data agreement template response message
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".read_all_data_agreement_template_response_handler.ReadAllDataAgreementTemplateResponseHandler"
)


class ReadAllDataAgreementTemplateResponseMessage(AgentMessage):
    """
    Message class for read all data agreement template response message.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = READ_ALL_DATA_AGREEMENT_TEMPLATE_RESPONSE

        # Message schema class
        schema_class = "ReadAllDataAgreementTemplateResponseMessageSchema"

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        body: typing.List[DataAgreementV1],
        **kwargs
    ):
        """
        Initialize a ReadAllDataAgreementTemplateResponseMessage message instance.
        """
        super().__init__(**kwargs)

        # Sender DID
        self.from_did = from_did

        # Recipient DID
        self.to_did = to_did

        # The time the message was created
        self.created_time = created_time

        # The list of data agreements
        self.body = body


class ReadAllDataAgreementTemplateResponseMessageSchema(AgentMessageSchema):
    """
    Schema class for read all data agreement template response message
    """

    class Meta:
        # The message class that this schema is for
        model_class = ReadAllDataAgreementTemplateResponseMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # body
    body = fields.List(
        fields.Nested(DataAgreementV1Schema),
        required=True,
        description="Data Agreement template"
    )
