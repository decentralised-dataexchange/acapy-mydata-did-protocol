from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext

from ..messages.problem_report import DataAgreementProblemReport
from ..manager import ADAManager

import json


class DataAgreementProblemReportHandler(BaseHandler):
    """Handle for data-agreements/1.0/problem-report message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data-agreements/1.0/problem-report message.
        """

        # Assert if received message is of type DataAgreementProblemReport
        assert isinstance(context.message, DataAgreementProblemReport)

        self._logger.info(
            "Received create-did message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        await ada_manager.process_data_agreement_problem_report_message(
            data_agreement_problem_report_message=context.message,
            receipt=context.message_receipt,
        )
