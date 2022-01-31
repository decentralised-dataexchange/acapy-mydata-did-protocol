from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.read_all_data_agreement_template_response import ReadAllDataAgreementTemplateResponseMessage

import json


class ReadAllDataAgreementTemplateResponseHandler(BaseHandler):
    """Handle for data-agreements/1.0/read-all-template-response message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data-agreements/1.0/read-all-template-response message.
        """

        # Assert if received message is of type ReadAllDataAgreementTemplateResponseMessage
        assert isinstance(context.message, ReadAllDataAgreementTemplateResponseMessage)

        self._logger.info(
            "Received data-agreements/1.0/read-all-template-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

