import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from mydata_did.v1_0.manager import ADAManager
from mydata_did.v1_0.messages.read_did_response import ReadDIDResponseMessage


class ReadDIDResponseHandler(BaseHandler):
    """
    Read DID response handler class
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic
        """

        # Assert if received message is of type ReadDIDResponseMessage
        assert isinstance(context.message, ReadDIDResponseMessage)

        self._logger.info(
            "Received read-did-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )

        # Check if connection is ready
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping read-did-response handler: %s",
                context.message_receipt.sender_did,
            )
            return

        # Initialize ADA manager
        mgr = ADAManager(context)

        # Process the read DID response
        await mgr.process_read_did_response_message(
            context.message, context.message_receipt
        )
