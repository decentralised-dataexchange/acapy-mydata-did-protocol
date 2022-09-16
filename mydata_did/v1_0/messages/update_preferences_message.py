from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import (
    PROTOCOL_PACKAGE,
    THIRDPARTY_DATA_SHARING_UPDATE_PREFERENCES,
)
from mydata_did.v1_0.models.update_preferences_model import (
    UpdatePreferencesBodyModel,
    UpdatePreferencesBodyModelSchema,
)

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers.update_preferences_message_handler.UpdatePreferencesMessageHandler"


class UpdatePreferencesMessage(AgentMessage):
    class Meta:
        handler_class = HANDLER_CLASS
        message_type = THIRDPARTY_DATA_SHARING_UPDATE_PREFERENCES
        schema_class = "UpdatePreferencesMessageSchema"

    def __init__(self, *, body: UpdatePreferencesBodyModel, **kwargs):
        super().__init__(**kwargs)

        self.body = body


class UpdatePreferencesMessageSchema(AgentMessageSchema):
    class Meta:
        model_class = UpdatePreferencesMessage
        unknown = EXCLUDE

    body = fields.Nested(UpdatePreferencesBodyModelSchema)
