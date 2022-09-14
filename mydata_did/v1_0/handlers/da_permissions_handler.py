from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from mydata_did.v1_0.messages.da_permissions import DAPermissionsMessage


class DAPermissionsMessageHandler(BaseHandler):
    """Data agreement permissions message handler."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle function

        Args:
            context (RequestContext): Request context.
            responder (BaseResponder): Responder.
        """

        # Assert the message type.
        assert isinstance(context.message, DAPermissionsMessage)

        # Initialize manager.
        mgr = V2ADAManager(context)

        # Process message.
        await mgr.process_da_permissions_message(
            context.message, context.message_receipt
        )
