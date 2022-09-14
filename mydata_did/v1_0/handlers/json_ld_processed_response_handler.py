import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from mydata_did.v1_0.messages.json_ld_processed_response import (
    JSONLDProcessedResponseMessage,
)


class JSONLDProcessedResponseHandler(BaseHandler):
    """Handle for JSONLD processed response message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for JSONLD processed response-data-response message.
        """

        # Assert if received message is of type JSONLDProcessedResponseMessage
        assert isinstance(context.message, JSONLDProcessedResponseMessage)

        self._logger.info(
            "Received JSONLD processed response-data-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )
