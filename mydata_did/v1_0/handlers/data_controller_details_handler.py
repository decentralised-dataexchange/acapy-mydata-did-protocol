import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from mydata_did.v1_0.messages.data_controller_details import (
    DataControllerDetailsMessage,
)


class DataControllerDetailsHandler(BaseHandler):
    """Handle for controller details message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Handle function for controller details message.
        """

        # Assert if received message is of type DataControllerDetailsMessage
        assert isinstance(context.message, DataControllerDetailsMessage)

        self._logger.info(
            "Received data-controller/1.0/details message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )

        # Initialize ADA manager
        mgr = V2ADAManager(context)

        # Call the function
        await mgr.process_data_controller_details_message(
            context.message,
            context.message_receipt,
        )
