from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import DATA_CONTROLLER_DETAILS, PROTOCOL_PACKAGE
from ..utils.regex import MYDATA_DID

# Handler class for data controller details
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_controller_details_handler.DataControllerDetailsHandler"
)

class DataControllerDetailsMessage(AgentMessage):
    """
    Message class for data controller details message.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = DATA_CONTROLLER_DETAILS

        # Message schema class
        schema_class = "DataControllerDetailsMessageSchema"

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        **kwargs
    ):
        """
        Initialize a DataControllerDetailsMessage message instance.
        """
        super().__init__(**kwargs)

        # Sender DID
        self.from_did = from_did

        # Recipient DID
        self.to_did = to_did

        # The time the message was created
        self.created_time = created_time


class DataControllerDetailsMessageSchema(AgentMessageSchema):
    """
    Schema class for data controller details message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataControllerDetailsMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")
