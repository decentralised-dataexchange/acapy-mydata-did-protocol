import typing
from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields

from ..message_types import DATA_CONTROLLER_DETAILS_RESPONSE, PROTOCOL_PACKAGE
from ..models.data_controller_model import DataController, DataControllerSchema
from ..utils.regex import MYDATA_DID

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

    def __init__(
        self,
        *,
        from_did,
        to_did,
        created_time,
        body: DataController,
        **kwargs
    ):
        """
        Initialize a DataControllerDetailsResponseMessage message instance.
        """
        super().__init__(**kwargs)

        # Sender DID
        self.from_did = from_did

        # Recipient DID
        self.to_did = to_did

        # The time the message was created
        self.created_time = created_time

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

    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # body
    body = fields.Nested(DataControllerSchema)
