from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.connection_request import ConnectionRequest

import json


class ConnectionRequestHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.info(
            f"ConnectionRequestHandler called with context {context}")
        assert isinstance(context.message, ConnectionRequest)

        self._logger.info(
            "Received connection request message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )



