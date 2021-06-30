from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.delete_did import DeleteDID
from ..manager import MyDataDIDManager

import json


class DeleteDIDHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.info(
            f"DeleteDIDHandler called with context {context}")
        assert isinstance(context.message, DeleteDID)

        self._logger.info(
            "Received delete-did message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping create-did handler: %s",
                context.message_receipt.sender_did,
            )
            return

        mgr = MyDataDIDManager(context)
        await mgr.process_delete_did_message(context.message, context.message_receipt)



