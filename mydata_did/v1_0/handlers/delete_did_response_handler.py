from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.delete_did_response import DeleteDIDResponseMessage
from ..manager import ADAManager

import json


class DeleteDIDResponseHandler(BaseHandler):
    """
    Handler to process response to delete-did message
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic
        """

        # Assert that received message is of type DeleteDIDResponse
        assert isinstance(context.message, DeleteDIDResponseMessage)

        self._logger.info(
            "Received delete-did-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if connection is ready.
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping delete-did-response handler: %s",
                context.message_receipt.sender_did,
            )
            return
        
        # Initialize ADA manager
        mgr = ADAManager(context)

        # Process the message
        await mgr.process_delete_did_response_message(context.message, context.message_receipt)



