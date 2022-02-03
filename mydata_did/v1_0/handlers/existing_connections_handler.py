from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.existing_connections import ExistingConnectionsMessage
from ..manager import ADAManager

import json


class ExistingConnectionsMessageHandler(BaseHandler):
    """Handle for connections/1.0/exists message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for connections/1.0/exists message.
        """

        # Assert if received message is of type ExistingConnectionsMessage
        assert isinstance(context.message, ExistingConnectionsMessage)

        self._logger.info(
            "Received connections/1.0/exists message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Call the function

        await ada_manager.process_existing_connections_message(
            existing_connections_message=context.message,
            receipt=context.message_receipt,
        )

