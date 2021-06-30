from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.delete_did_response import DeleteDIDResponse
from ..manager import MyDataDIDManager

import json


class DeleteDIDResponseHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.info(
            f"DeleteDIDResponseHandler called with context {context}")
        assert isinstance(context.message, DeleteDIDResponse)

        self._logger.info(
            "Received delete-did-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping delete-did-response handler: %s",
                context.message_receipt.sender_did,
            )
            return

        mgr = MyDataDIDManager(context)
        await mgr.process_delete_did_response_message(context.message, context.message_receipt)



