from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.json_ld_processed import JSONLDProcessedMessage
from ..manager import ADAManager

import json


class JSONLDProcessedHandler(BaseHandler):
    """Handle for json-ld/1.0/processed-data message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for json-ld/1.0/processed-data message.
        """

        # Assert if received message is of type JSONLDProcessedMessage
        assert isinstance(context.message, JSONLDProcessedMessage)

        self._logger.info(
            "Received json-ld/1.0/processed-data message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Call the function

        await ada_manager.process_json_ld_processed_message(
            json_ld_processed_message=context.message,
            receipt=context.message_receipt,
        )

