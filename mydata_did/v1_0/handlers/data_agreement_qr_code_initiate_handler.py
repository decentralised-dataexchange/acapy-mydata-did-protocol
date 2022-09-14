import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from mydata_did.v1_0.messages.data_agreement_qr_code_initiate import (
    DataAgreementQrCodeInitiateMessage,
)


class DataAgreementQrCodeInitiateHandler(BaseHandler):
    """Handler for qr code initiate message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Handler function for qr code initiate message.
        """

        # Assert if received message is of type DataAgreementQrCodeInitiateMessage
        assert isinstance(context.message, DataAgreementQrCodeInitiateMessage)

        self._logger.info(
            "Received data-agreement-qr-code/1.0/initiate message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )

        # Initialize ADA manager
        mgr = V2ADAManager(context)

        # Call the function
        await mgr.process_data_agreement_qr_code_initiate_message(
            context.message,
            context.message_receipt,
        )
