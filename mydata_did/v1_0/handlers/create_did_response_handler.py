from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.create_did_response import CreateDIDResponseMessage
from ..manager import ADAManager

import json


class CreateDIDResponseHandler(BaseHandler):
    """
    Create DID response handler class
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic
        """

        # Assert if received message is of type CreateDIDResponseMessage
        assert isinstance(context.message, CreateDIDResponseMessage)

        self._logger.info(
            "Received create-did-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if connection is ready
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping create-did-response handler: %s",
                context.message_receipt.sender_did,
            )
            return

        # Initialize ADA manager
        mgr = ADAManager(context)

        # Process the create DID response
        await mgr.process_create_did_response_message(context.message, context.message_receipt)
