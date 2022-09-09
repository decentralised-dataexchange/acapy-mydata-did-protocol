from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from dexa_sdk.managers.ada_manager import V2ADAManager
from ..messages.existing_connections import ExistingConnectionsMessage


class ExistingConnectionsMessageHandler(BaseHandler):
    """Handler for existing connections message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Handle function.
        """

        # Assert message type.
        assert isinstance(context.message, ExistingConnectionsMessage)

        # Initialize ADA manager
        mgr = V2ADAManager(context)

        # Call the function
        await mgr.process_existing_connections_message(
            context.message,
            context.message_receipt,
        )
