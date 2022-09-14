from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    DATA_CONTROLLER_DETAILS_RESPONSE,
    PROTOCOL_PACKAGE,
)
from mydata_did.v1_0.models.data_controller_model import (
    DataController,
    DataControllerSchema,
)

# Handler class for data controller details response
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_controller_details_response_handler.DataControllerDetailsResponseHandler"
)


class DataControllerDetailsResponseMessage(AgentMessage):
    """
    Message class for data controller details response message.
    """

    class Meta:
        # Handler class that can handle this message
        handler_class = HANDLER_CLASS

        # Message type
        message_type = DATA_CONTROLLER_DETAILS_RESPONSE

        # Message schema class
        schema_class = "DataControllerDetailsResponseMessageSchema"

    def __init__(self, *, body: DataController, **kwargs):
        """
        Initialize a DataControllerDetailsResponseMessage message instance.
        """
        super().__init__(**kwargs)

        # Data controller details
        self.body = body


class DataControllerDetailsResponseMessageSchema(AgentMessageSchema):
    """
    Schema class for data controller details response message
    """

    class Meta:
        # The message class that this schema is for
        model_class = DataControllerDetailsResponseMessage

        # Unknown fields to exclude from the schema (handled by marshmallow)
        unknown = EXCLUDE

    # body
    body = fields.Nested(DataControllerSchema)
