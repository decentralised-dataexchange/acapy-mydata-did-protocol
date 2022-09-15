from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE
from mydata_did.v1_0.message_types import (
    PROTOCOL_PACKAGE,
    THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES,
)

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.fetch_preferences_handler.FetchPreferencesHandler"
)


class FetchPreferencesMessage(AgentMessage):
    class Meta:
        handler_class = HANDLER_CLASS
        message_type = THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES
        schema_class = "FetchPreferencesMessageSchema"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class FetchPreferencesMessageSchema(AgentMessageSchema):
    class Meta:
        model_class = FetchPreferencesMessage
        unknown = EXCLUDE
