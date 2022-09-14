from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE
from mydata_did.v1_0.message_types import DATA_CONTROLLER_DETAILS, PROTOCOL_PACKAGE

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

    def __init__(self, **kwargs):
        """
        Initialize a DataControllerDetailsMessage message instance.
        """
        super().__init__(**kwargs)


class DataControllerDetailsMessageSchema(AgentMessageSchema):
    """
    Schema class for data controller details message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataControllerDetailsMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE
