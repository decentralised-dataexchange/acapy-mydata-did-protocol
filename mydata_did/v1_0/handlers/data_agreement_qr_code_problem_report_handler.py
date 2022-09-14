import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from mydata_did.v1_0.messages.data_agreement_qr_code_problem_report import (
    DataAgreementQrCodeProblemReport,
)


class DataAgreementQrCodeProblemReportHandler(BaseHandler):
    """Handle for data-agreement-qr-code/1.0/problem-report message"""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data-agreement-qr-code/1.0/problem-report message.
        """

        # Assert if received message is of type DataAgreementQrCodeProblemReport
        assert isinstance(context.message, DataAgreementQrCodeProblemReport)

        self._logger.info(
            "Received data-agreement-qr-code/1.0/problem-report message: \n%s",
            json.dumps(context.message.serialize(), indent=4),
        )
