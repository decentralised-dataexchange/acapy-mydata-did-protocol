from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.create_did_response import CreateDIDResponse
from ..manager import MyDataDIDManager

import json


class CreateDIDResponseHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.info(
            f"CreateDIDHandler called with context {context}")
        assert isinstance(context.message, CreateDIDResponse)

        self._logger.info(
            "Received create-did-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping create-did-response handler: %s",
                context.message_receipt.sender_did,
            )
            return

        mgr = MyDataDIDManager(context)
        await mgr.process_create_did_response_message(context.message, context.message_receipt)



