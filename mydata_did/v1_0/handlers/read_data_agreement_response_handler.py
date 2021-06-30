from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.read_data_agreement_response import ReadDataAgreementResponse
from ..manager import ADAManager

import json

class ReadDataAgreementResponseHandler(BaseHandler):

    async def handle(self, context: RequestContext, responder: BaseResponder):
        self._logger.debug("ReadDataAgreementResponseHandler called")
        assert isinstance(context.message, ReadDataAgreementResponse)

        self._logger.info("Received read data agreement response message: %s", json.dumps(context.message.serialize(), indent=4))

        mgr: ADAManager = ADAManager(context)
        await mgr.process_read_data_agreement_response_message(context.message, context.message_receipt)