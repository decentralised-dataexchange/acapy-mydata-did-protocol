from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.data_controller_details import DataControllerDetailsMessage
from ..manager import ADAManager

import json


class DataControllerDetailsHandler(BaseHandler):
    """Handle for data-controller/1.0/details message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data-controller/1.0/details message.
        """

        # Assert if received message is of type DataControllerDetailsMessage
        assert isinstance(context.message, DataControllerDetailsMessage)

        self._logger.info(
            "Received data-controller/1.0/details message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Call the function

        await ada_manager.process_data_controller_details_message(
            data_controller_details_message=context.message,
            receipt=context.message_receipt,
        )

