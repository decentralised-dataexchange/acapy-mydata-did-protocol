from enum import Enum
from marshmallow import EXCLUDE, fields, validate

from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema

from ..message_types import DATA_AGREEMENT_PROBLEM_REPORT, MYDATA_DID_PROBLEM_REPORT, PROTOCOL_PACKAGE
from ..utils.regex import MYDATA_DID

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".problem_report_handler.ProblemReportHandler"
)

class ProblemReportReason(str, Enum):
    """Supported reason codes."""

    DID_EXISTS = "mydata_did_exists"
    DIDDOC_SIGNATURE_VERIFICATION_FAILED = "mydata_diddoc_signature_verification_failed"
    DIDCOMM_MESSAGE_TO_FROM_INVALID = "mydata_didcomm_message_sender_recipient_did_invalid"
    DID_INVALID = "invalid_decentralised_identifier"
    DID_NOT_FOUND = "did_not_found"
    DID_REVOKED = "did_revoked"


class ProblemReport(AgentMessage):
    """Base class representing a connection problem report message."""

    class Meta:
        """Connection problem report metadata."""

        handler_class = HANDLER_CLASS
        message_type = MYDATA_DID_PROBLEM_REPORT
        schema_class = "ProblemReportSchema"

    def __init__(self, *, problem_code: str = None, explain: str = None, from_did, to_did, created_time, **kwargs):
        """
        Initialize a ProblemReport message instance.

        Args:
            explain: The localized error explanation
            problem_code: The standard error identifier
        """
        super().__init__(**kwargs)
        self.explain = explain
        self.problem_code = problem_code
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time


class ProblemReportSchema(AgentMessageSchema):
    """Schema for ProblemReport base class."""

    class Meta:
        """Metadata for problem report schema."""

        model_class = ProblemReport
        unknown = EXCLUDE
    
    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
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
            choices=[prr.value for prr in ProblemReportReason],
            error="Value {input} must be one of {choices}.",
        ),
        example=ProblemReportReason.DID_EXISTS.value,
    )

# Handler class path for Data Agreement Problem Report (data-agreements/1.0/problem-report) message
DATA_AGREEMENT_PROBLEM_REPORT_HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_problem_report_handler.DataAgreementProblemReportHandler"
)

class DataAgreementProblemReportReason(str, Enum):
    """Supported reason codes."""

    # Triggered when creation of data agreement failed.
    FAILED_TO_CREATE_DATA_AGREEMENT = "failed_to_create_data_agreement"

    # Triggered when failed to read data agreement.
    FAILED_TO_READ_DATA_AGREEMENT = "failed_to_read_data_agreement"

    # Triggered when failed to update data agreeement.
    FAILED_TO_UPDATE_DATA_AGREEMENT = "failed_to_update_data_agreement"

    # Triggered when failed to delete data agreement.
    FAILED_TO_DELETE_DATA_AGREEMENT = "failed_to_delete_data_agreement"

    # Triggered when data agreement was not found.
    DATA_AGREEMENT_NOT_FOUND = "data_agreement_not_found"

    # Triggered when data agreement is already revoked.
    DATA_AGREEMENT_REVOKED = "data_agreement_revoked"

    # Triggered when data agreement is invalid.
    DATA_AGREEMENT_INVALID = "invalid_data_agreement"

    # Triggered when data agreement is expired.
    DATA_AGREEMENT_EXPIRED = "data_agreement_expired"

class DataAgreementProblemReport(AgentMessage):
    """Base class representing a data agreement problem report message."""

    class Meta:
        """Data agreement problem report metadata."""

        handler_class = DATA_AGREEMENT_PROBLEM_REPORT_HANDLER_CLASS
        message_type = DATA_AGREEMENT_PROBLEM_REPORT
        schema_class = "DataAgreementProblemReportSchema"

    def __init__(
        self,
        *,
        problem_code: str = None,
        explain: str = None,
        from_did,
        to_did,
        created_time,
        **kwargs
    ):
        """
        Initialize a DataAgreementProblemReport message instance.

        Args:
            explain: The localized error explanation
            problem_code: The standard error identifier
        """
        super().__init__(**kwargs)
        self.explain = explain
        self.problem_code = problem_code
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time

class DataAgreementProblemReportSchema(AgentMessageSchema):

    class Meta:
        """Metadata for data agreement problem report schema."""

        model_class = DataAgreementProblemReport
        unknown = EXCLUDE

    from_did = fields.Str(data_key="from", **MYDATA_DID)
    to_did = fields.Str(data_key="to", **MYDATA_DID)
    created_time = fields.Str(data_key="created_time")
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
            choices=[dapr.value for dapr in DataAgreementProblemReportReason],
            error="Value {input} must be one of {choices}.",
        ),
        example=DataAgreementProblemReportReason.FAILED_TO_CREATE_DATA_AGREEMENT.value,
    )
