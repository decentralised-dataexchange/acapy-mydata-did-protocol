import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from mydata_did.v1_0.messages.data_controller_details_response import (
    DataControllerDetailsResponseMessage,
)


class DataControllerDetailsResponseHandler(BaseHandler):
    """Handle for data-controller/1.0/details-response message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data-controller/1.0/details-response message.
        """

        # Assert if received message is of type DataControllerDetailsResponseMessage
        assert isinstance(context.message, DataControllerDetailsResponseMessage)

        self._logger.info(
            "Received data-controller/1.0/details-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )
