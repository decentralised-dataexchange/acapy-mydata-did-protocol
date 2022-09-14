import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from mydata_did.v1_0.messages.json_ld_processed import JSONLDProcessedMessage


class JSONLDProcessedHandler(BaseHandler):
    """Handle for JSONLD processed message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic.
        """

        assert isinstance(context.message, JSONLDProcessedMessage)

        self._logger.info(
            "Received JSONLD processed message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )

        # Initialize ADA manager
        mgr = V2ADAManager(context)

        # Call the function

        await mgr.process_json_ld_processed_message(
            json_ld_processed_message=context.message,
            receipt=context.message_receipt,
        )
