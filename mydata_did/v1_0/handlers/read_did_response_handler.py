from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.read_did_response import ReadDIDResponse
from ..manager import ADAManager

import json


class ReadDIDResponseHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.info(
            f"ReadDIDResponseHandler called with context {context}")
        assert isinstance(context.message, ReadDIDResponse)

        self._logger.info(
            "Received read-did-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping read-did-response handler: %s",
                context.message_receipt.sender_did,
            )
            return

        mgr = ADAManager(context)
        await mgr.process_read_did_response_message(context.message, context.message_receipt)



