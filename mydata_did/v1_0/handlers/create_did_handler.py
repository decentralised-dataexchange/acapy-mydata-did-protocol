from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.create_did import CreateDID
from ..manager import ADAManager

import json


class CreateDIDHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.info(
            f"CreateDIDHandler called with context {context}")
        assert isinstance(context.message, CreateDID)

        self._logger.info(
            "Received create-did message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping create-did handler: %s",
                context.message_receipt.sender_did,
            )
            return

        mgr = ADAManager(context)
        await mgr.process_create_did_message(context.message, context.message_receipt)



