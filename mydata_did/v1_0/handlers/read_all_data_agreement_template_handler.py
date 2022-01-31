from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.read_all_data_agreement_template import ReadAllDataAgreementTemplateMessage
from ..manager import ADAManager

import json


class ReadAllDataAgreementTemplateHandler(BaseHandler):
    """Handle for data-agreements/1.0/read-all-template message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data-agreements/1.0/read-all-template message.
        """

        # Assert if received message is of type ReadAllDataAgreementTemplateMessage
        assert isinstance(context.message, ReadAllDataAgreementTemplateMessage)

        self._logger.info(
            "Received data-agreements/1.0/read-all-template message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Call the function

        await ada_manager.process_read_all_data_agreement_template_message(
            read_all_data_agreement_template_message=context.message,
            receipt=context.message_receipt,
        )

