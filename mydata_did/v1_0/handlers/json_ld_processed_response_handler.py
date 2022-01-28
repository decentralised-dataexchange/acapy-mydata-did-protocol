from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.json_ld_processed_response import JSONLDProcessedResponseMessage
from ..manager import ADAManager

import json


class JSONLDProcessedResponseHandler(BaseHandler):
    """Handle for json-ld/1.0/processed message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for json-ld/1.0/processed-data-response message.
        """

        # Assert if received message is of type JSONLDProcessedResponseMessage
        assert isinstance(context.message, JSONLDProcessedResponseMessage)

        self._logger.info(
            "Received json-ld/1.0/processed-data-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

