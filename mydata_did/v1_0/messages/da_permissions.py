from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.message_types import DA_PERMISSIONS, PROTOCOL_PACKAGE
from mydata_did.v1_0.models.da_permissions_model import (
    DAPermissionsBodyModel,
    DAPermissionsBodyModelSchema,
)

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.da_permissions_handler.DAPermissionsMessageHandler"
)


class DAPermissionsMessage(AgentMessage):
    class Meta:
        handler_class = HANDLER_CLASS
        message_type = DA_PERMISSIONS
        schema_class = "DAPermissionsMessageSchema"

    def __init__(self, *, body: DAPermissionsBodyModel, **kwargs):
        super().__init__(**kwargs)

        self.body = body


class DAPermissionsMessageSchema(AgentMessageSchema):
    class Meta:
        model_class = DAPermissionsMessage
        unknown = EXCLUDE

    body = fields.Nested(DAPermissionsBodyModelSchema)
