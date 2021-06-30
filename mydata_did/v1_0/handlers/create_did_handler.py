from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.create_did import CreateDIDMessage
from ..manager import ADAManager

import json


class CreateDIDHandler(BaseHandler):
    """
    CreateDIDHandler is called by the Agent when it receives a create-did message.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for create-did request.
        """

        # Assert if received message is of type CreateDIDMessage
        assert isinstance(context.message, CreateDIDMessage)

        self._logger.info(
            "Received create-did message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if the connection is ready.
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping create-did handler: %s",
                context.message_receipt.sender_did,
            )
            return
        
        # Initialize ADA manager
        mgr = ADAManager(context)

        # Process the create-did message.
        await mgr.process_create_did_message(context.message, context.message_receipt)



