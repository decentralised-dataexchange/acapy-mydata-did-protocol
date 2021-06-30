from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.read_did import ReadDID
from ..manager import MyDataDIDManager

import json


class ReadDIDHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.info(
            f"ReadDIDHandler called with context {context}")
        assert isinstance(context.message, ReadDID)

        self._logger.info(
            "Received read-did message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping create-did handler: %s",
                context.message_receipt.sender_did,
            )
            return

        mgr = MyDataDIDManager(context)
        await mgr.process_read_did_message(context.message, context.message_receipt)



