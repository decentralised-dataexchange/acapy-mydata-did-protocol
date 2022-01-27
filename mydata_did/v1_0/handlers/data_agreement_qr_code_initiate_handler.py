from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.data_agreement_qr_code_initiate import DataAgreementQrCodeInitiateMessage
from ..manager import ADAManager

import json


class DataAgreementQrCodeInitiateHandler(BaseHandler):
    """Handle for data-agreement-qr-code/1.0/initiate message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data-agreement-qr-code/1.0/initiate message.
        """

        # Assert if received message is of type DataAgreementQrCodeInitiateMessage
        assert isinstance(context.message, DataAgreementQrCodeInitiateMessage)

        self._logger.info(
            "Received data-agreement-qr-code/1.0/initiate message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Call the function

        await ada_manager.process_data_agreement_qr_code_initiate_message(
            data_agreement_qr_code_initiate_message=context.message,
            receipt=context.message_receipt,
        )

