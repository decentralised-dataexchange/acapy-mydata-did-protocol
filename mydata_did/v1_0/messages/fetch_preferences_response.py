from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    PROTOCOL_PACKAGE,
    THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES_RESPONSE,
)
from mydata_did.v1_0.models.fetch_preferences_response_model import (
    FetchPreferencesResponseBody,
    FetchPreferencesResponseBodySchema,
)

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers.fetch_preferences_response_handler.FetchPreferencesResponseHandler"


class FetchPreferencesResponseMessage(AgentMessage):
    class Meta:
        handler_class = HANDLER_CLASS
        message_type = THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES_RESPONSE
        schema_class = "FetchPreferencesResponseMessageSchema"

    def __init__(self, body: FetchPreferencesResponseBody = None, **kwargs):
        super().__init__(**kwargs)

        self.body = body


class FetchPreferencesResponseMessageSchema(AgentMessageSchema):
    class Meta:
        model_class = FetchPreferencesResponseMessage
        unknown = EXCLUDE

    body = fields.Nested(FetchPreferencesResponseBodySchema, required=False)
