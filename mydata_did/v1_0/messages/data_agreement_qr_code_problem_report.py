from enum import Enum

from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import EXCLUDE, fields, validate
from mydata_did.v1_0.message_types import (
    DATA_AGREEMENT_QR_CODE_WORKFLOW_PROBLEM_REPORT,
    PROTOCOL_PACKAGE,
)

# Handler class path for Data Agreement Qr code workflow
# Problem Report (data-agreement-qr-code/1.0/problem-report) message
DATA_AGREEMENT_QR_CODE_WORKFLOW_PROBLEM_REPORT_HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_qr_code_problem_report_handler.DataAgreementQrCodeProblemReportHandler"
)


class DataAgreementQrCodeProblemReportReason(str, Enum):
    """Supported reason codes."""

    # Trigger when qr code identifier provided is invalid.
    INVALID_QR_ID = "invalid_qr_id"

    # Trigger QR code is already scanned.
    QR_CODE_SCANNED_ONCE = "qr_code_scanned_once"

    # Failed to process qr code workflow initiate message due to an internal error.
    FAILED_TO_PROCESS_QR_CODE_INITIATE_MESSAGE = (
        "failed_to_process_qr_code_initiate_message"
    )


class DataAgreementQrCodeProblemReport(AgentMessage):
    """Base class representing a data agreement qr code problem report message."""

    class Meta:
        """Data agreement qr code problem report metadata."""

        handler_class = DATA_AGREEMENT_QR_CODE_WORKFLOW_PROBLEM_REPORT_HANDLER_CLASS
        message_type = DATA_AGREEMENT_QR_CODE_WORKFLOW_PROBLEM_REPORT
        schema_class = "DataAgreementQrCodeProblemReportSchema"

    def __init__(
        self,
        *,
        problem_code: str = None,
        explain: str = None,
        qr_id: str = None,
        **kwargs,
    ):
        """
        Initialize a DataAgreementQrCodeProblemReport message instance.

        Args:
            explain: The localized error explanation
            problem_code: The standard error identifier
            from_did: Sender DID
            to_did: Receipient DID
            created_time: The timestamp of the message
            qr_id: Qr code identifier
        """
        super().__init__(**kwargs)
        self.explain = explain
        self.problem_code = problem_code
        self.qr_id = qr_id


class DataAgreementQrCodeProblemReportSchema(AgentMessageSchema):
    """
    Data agreement qr code problem report schema.
    """

    class Meta:
        """Metadata for data agreement qr code problem report schema."""

        model_class = DataAgreementQrCodeProblemReport
        unknown = EXCLUDE

    explain = fields.Str(
        required=False,
        description="Localized error explanation",
        example="Invitation not accepted",
    )
    problem_code = fields.Str(
        data_key="problem-code",
        required=False,
        description="Standard error identifier",
        validate=validate.OneOf(
            choices=[dapr.value for dapr in DataAgreementQrCodeProblemReportReason],
            error="Value {input} must be one of {choices}.",
        ),
        example=DataAgreementQrCodeProblemReportReason.QR_CODE_SCANNED_ONCE.value,
    )
    qr_id = fields.Str(
        data_key="qr-id",
        required=False,
        description="Qr code identifier",
        example=UUIDFour.EXAMPLE,
    )
