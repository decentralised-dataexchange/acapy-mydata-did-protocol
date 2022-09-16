from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from mydata_did.v1_0.messages.update_preferences_message import UpdatePreferencesMessage


class UpdatePreferencesMessageHandler(BaseHandler):
    """Update preferences message handler."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle function

        Args:
            context (RequestContext): Request context.
            responder (BaseResponder): Responder.
        """

        # Assert the message type.
        assert isinstance(context.message, UpdatePreferencesMessage)

        # Initialize manager.
        mgr = V2ADAManager(context)

        # Process message.
        await mgr.process_update_preferences_message(
            context.message, context.message_receipt
        )
