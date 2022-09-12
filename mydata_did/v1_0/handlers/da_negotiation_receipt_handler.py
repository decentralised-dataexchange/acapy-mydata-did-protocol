from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from dexa_sdk.managers.ada_manager import V2ADAManager
from ..messages.da_negotiation_receipt import DataAgreementNegotiationReceiptMessage


class DataAgreementNegotiationReceiptMessageHandler(BaseHandler):
    """Data agreement negotiation receipt message handler."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle function

        Args:
            context (RequestContext): Request context.
            responder (BaseResponder): Responder.
        """

        # Assert the message type.
        assert isinstance(context.message, DataAgreementNegotiationReceiptMessage)

        # Initialize manager.
        mgr = V2ADAManager(context)

        # Process read-did message
        await mgr.process_read_did_message(context.message, context.message_receipt)
