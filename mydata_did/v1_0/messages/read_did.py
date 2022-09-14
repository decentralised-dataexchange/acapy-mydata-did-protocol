from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import PROTOCOL_PACKAGE, READ_DID
from mydata_did.v1_0.utils.regex import MYDATA_DID

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers" ".read_did_handler.ReadDIDHandler"


class ReadDIDMessageBody(BaseModel):
    """
    Read DID message body class
    """

    class Meta:

        # Schema class
        schema_class = "ReadDIDMessageBodySchema"

    def __init__(self, *, did: str, **kwargs):
        """
        Initialize ReadDIDMessageBody instance

        Args:
            did: The DID to be read
        """

        super().__init__(**kwargs)

        # The DID to be read
        self.did = did


class ReadDIDMessageBodySchema(BaseModelSchema):
    """
    Read DID message body schema class
    """

    class Meta:
        # Message body model
        model_class = ReadDIDMessageBody

        # Unknown fields to exclude from the schema
        unknown = EXCLUDE

    # The DID to be read
    did = fields.Str(data_key="did", **MYDATA_DID)


class ReadDIDMessage(AgentMessage):
    """
    Message class for reading a DID.
    """

    class Meta:

        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = READ_DID

        # Message schema class
        schema_class = "ReadDIDMessageSchema"

    def __init__(
        self, *, from_did, to_did, created_time, body: ReadDIDMessageBody, **kwargs
    ):
        """
        Initialize a ReadDIDMessage message instance.

        Args:
            from_did: Sender DID
            to_did: Reciepient DID
            created_time: Time the message was created
            body: Message body
        """

        super().__init__(**kwargs)

        # Set attributes
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.body = body


class ReadDIDMessageSchema(AgentMessageSchema):
    """
    Schema class for reading a DID.
    """

    class Meta:

        # The message class that this schema is for
        model_class = ReadDIDMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # Message body
    body = fields.Nested(ReadDIDMessageBodySchema, required=True)
