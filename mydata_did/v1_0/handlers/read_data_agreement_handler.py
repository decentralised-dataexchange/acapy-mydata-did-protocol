from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.read_data_agreement import ReadDataAgreement
from ..manager import ADAManager

import json

class ReadDataAgreementHandler(BaseHandler):
    """
    Handler class for read data agreement
    """
    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic
        """
        self._logger.debug("ReadDataAgreementHandler called")
        assert isinstance(context.message, ReadDataAgreement)

        self._logger.info("Received read data agreement message: %s", json.dumps(context.message.serialize(), indent=4))

        mgr : ADAManager= ADAManager(context)
        await mgr.process_read_data_agreement_message(read_data_agreement_message=context.message, receipt=context.message_receipt)
