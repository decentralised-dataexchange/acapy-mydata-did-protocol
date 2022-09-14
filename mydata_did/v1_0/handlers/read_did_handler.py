import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from mydata_did.v1_0.manager import ADAManager
from mydata_did.v1_0.messages.read_did import ReadDIDMessage


class ReadDIDHandler(BaseHandler):
    """
    Read DID message handler
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for read-did request.
        """

        # Assert if received message is of type ReadDIDMessage
        assert isinstance(context.message, ReadDIDMessage)

        self._logger.info(
            "Received read-did message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )

        # Initialize ADA manager
        mgr = ADAManager(context)

        # Process read-did message
        await mgr.process_read_did_message(context.message, context.message_receipt)
