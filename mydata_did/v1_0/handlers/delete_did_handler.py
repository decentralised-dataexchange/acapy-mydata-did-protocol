from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.delete_did import DeleteDIDMessage
from ..manager import ADAManager

import json


class DeleteDIDHandler(BaseHandler):
    """
    Handle a message to delete a DID.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for delete DID.
        """

        # Assert that the message is the correct type
        assert isinstance(context.message, DeleteDIDMessage)

        self._logger.info(
            "Received delete-did message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if connection is ready.
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping delete-did handler: %s",
                context.message_receipt.sender_did,
            )
            return
        
        # Initialize ADA manager
        mgr = ADAManager(context)

        # Process the message
        await mgr.process_delete_did_message(context.message, context.message_receipt)



