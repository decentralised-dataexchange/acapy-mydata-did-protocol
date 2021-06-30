"""Represents a connection request message."""

from marshmallow import EXCLUDE, fields

from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.protocols.connections.v1_0.models.connection_detail import ConnectionDetail, ConnectionDetailSchema
from aries_cloudagent.protocols.connections.v1_0.messages.connection_request import (
    ConnectionRequest,
    ConnectionRequestSchema
)

from ..message_types import PROTOCOL_PACKAGE, CONNECTION_REQUEST


HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".connection_request_handler.ConnectionRequestHandler"
)


class ConnectionRequest(ConnectionRequest):

    class Meta(ConnectionRequest.Meta):
        handler_class = HANDLER_CLASS
        message_type = CONNECTION_REQUEST
        schema_class = "ConnectionRequestSchema"

class ConnectionRequestSchema(ConnectionRequestSchema):

    class Meta(ConnectionRequestSchema.Meta):
        model_class = ConnectionRequest

