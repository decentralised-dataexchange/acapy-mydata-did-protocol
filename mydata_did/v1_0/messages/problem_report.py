from enum import Enum
from marshmallow import EXCLUDE, fields, validate

from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema

from ..message_types import DATA_AGREEMENT_PROBLEM_REPORT, MYDATA_DID_PROBLEM_REPORT, PROTOCOL_PACKAGE
from ..utils.regex import MYDATA_DID

# Handler class
HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".mydata_did_problem_report_handler.MyDataDIDProblemReportHandler"
)


class MyDataDIDProblemReportMessageReason(str, Enum):
    """Supported reason codes for mydata-did message family."""

    # MyData DID exists.
    DID_EXISTS = "mydata_did_exists"

    # DIDComm message body signature verification failed.
    MESSAGE_BODY_SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"

    # MyData DID not found.
    DID_NOT_FOUND = "mydata_did_not_found"

    # MyData DID revoked.
    DID_REVOKED = "mydata_did_revoked"


class MyDataDIDProblemReportMessage(AgentMessage):
    """
    Problem report message for MyData DID protocol.
    """

    class Meta:
        # Handler class that should handle this message
        handler_class = HANDLER_CLASS

        # Message type for this message
        message_type = MYDATA_DID_PROBLEM_REPORT

        # Schema for this message
        schema_class = "MyDataDIDProblemReportMessageSchema"

    def __init__(
        self,
        *,
        problem_code: str = None,
        explain: str = None,
        from_did: str = None,
        to_did: str = None,
        created_time: str = None,
        **kwargs
    ):
        """
        Initialize mydata-did problem report message instance.

        Args:
            problem_code: Reason code for the problem.
            explain: Explanation for the problem.
            from_did: DID of the sender.
            to_did: DID of the receiver.
            created_time: Time when the problem report was created.
        """

        super().__init__(**kwargs)

        # Set attributes
        self.explain = explain
        self.problem_code = problem_code
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time


class MyDataDIDProblemReportMessageSchema(AgentMessageSchema):
    """
    Schema for mydata-did problem report message.
    """

    class Meta:
        # Message class this schema is derived from.
        model_class = MyDataDIDProblemReportMessage

        # Unknow fields are excluded.
        unknown = EXCLUDE
    
    # From DID
    from_did = fields.Str(data_key="from", **MYDATA_DID)

    # To DID
    to_did = fields.Str(data_key="to", **MYDATA_DID)

    # Created time
    created_time = fields.Str(data_key="created_time")

    # Explaination for the problem
    explain = fields.Str(
        required=False,
        description="Localized error explanation",
        example="Invitation not accepted",
    )

    # Reason code for the problem
    problem_code = fields.Str(
        data_key="problem-code",
        required=False,
        description="Standard error identifier",
        validate=validate.OneOf(
            choices=[prr.value for prr in MyDataDIDProblemReportMessageReason],
            error="Value {input} must be one of {choices}.",
        ),
        example=MyDataDIDProblemReportMessageReason.DID_EXISTS.value,
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
