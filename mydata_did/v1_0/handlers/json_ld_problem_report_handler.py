from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.json_ld_problem_report import JSONLDProblemReport
from ..manager import ADAManager

import json


class JSONLDProblemReportHandler(BaseHandler):
    """Handle for json-ld/1.0/problem-report message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for json-ld/1.0/problem-report message.
        """

        # Assert if received message is of type JSONLDProblemReport
        assert isinstance(context.message, JSONLDProblemReport)

        self._logger.info(
            "Received json-ld/1.0/problem-report message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

