from enum import Enum

from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import EXCLUDE, fields, validate
from mydata_did.v1_0.message_types import (
    DATA_AGREEMENT_NEGOTIATION_PROBLEM_REPORT,
    DATA_AGREEMENT_PROBLEM_REPORT,
    DATA_AGREEMENT_TERMINATION_PROBLEM_REPORT,
    MYDATA_DID_PROBLEM_REPORT,
    PROTOCOL_PACKAGE,
)
from mydata_did.v1_0.utils.regex import MYDATA_DID

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
        **kwargs,
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

    # Triggered when data agreement was not found.
    DATA_AGREEMENT_NOT_FOUND = "data_agreement_not_found"

    # Triggered when read-data-agreement failed due to processing error.
    READ_DATA_AGREEMENT_FAILED = "read_data_agreement_failed"


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
        from_did: str = None,
        to_did: str = None,
        created_time: str = None,
        **kwargs,
    ):
        """
        Initialize a DataAgreementProblemReport message instance.
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
        example=DataAgreementProblemReportReason.DATA_AGREEMENT_NOT_FOUND.value,
    )


# Handler class path for Data Agreement Negotiation Problem Report (data-agreement-negotiation/1.0/problem-report) message
DATA_AGREEMENT_NEGOTIATION_PROBLEM_REPORT_HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_negotiation_problem_report_handler.DataAgreementNegotiationProblemReportHandler"
)


class DataAgreementNegotiationProblemReportReason(str, Enum):
    """Supported reason codes."""

    # Trigger when data agreement signature verification fails
    SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"

    # Trigger when controller (Organisation) DID is not present in remote did registry
    CONTROLLER_DID_INVALID = "controller_did_invalid"

    # Trigger when principle (Data Subject) DID is invalid
    PRINCIPLE_DID_INVALID = "principle_did_invalid"

    # Trigger when data agreement context is invalid
    DATA_AGREEMENT_CONTEXT_INVALID = "data_agreement_context_invalid"


class DataAgreementNegotiationProblemReport(AgentMessage):
    """Base class representing a data agreement negotiation problem report message."""

    class Meta:
        """Data agreement negotiation problem report metadata."""

        handler_class = DATA_AGREEMENT_NEGOTIATION_PROBLEM_REPORT_HANDLER_CLASS
        message_type = DATA_AGREEMENT_NEGOTIATION_PROBLEM_REPORT
        schema_class = "DataAgreementNegotiationProblemReportSchema"

    def __init__(
        self,
        *,
        problem_code: str = None,
        explain: str = None,
        from_did: str = None,
        to_did: str = None,
        created_time: str = None,
        data_agreement_id: str = None,
        **kwargs,
    ):
        """
        Initialize a DataAgreementNegotiationProblemReport message instance.

        Args:
            explain: The localized error explanation
            problem_code: The standard error identifier
            from_did: Sender DID
            to_did: Receipient DID
            created_time: The timestamp of the message
            data_agreement_id: The data agreement identifier
        """
        super().__init__(**kwargs)
        self.explain = explain
        self.problem_code = problem_code
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.data_agreement_id = data_agreement_id


class DataAgreementNegotiationProblemReportSchema(AgentMessageSchema):
    """
    Data agreement negotiation problem report schema.
    """

    class Meta:
        """Metadata for data agreement negotiation problem report schema."""

        model_class = DataAgreementNegotiationProblemReport
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
            choices=[
                dapr.value for dapr in DataAgreementNegotiationProblemReportReason
            ],
            error="Value {input} must be one of {choices}.",
        ),
        example=DataAgreementNegotiationProblemReportReason.SIGNATURE_VERIFICATION_FAILED.value,
    )
    data_agreement_id = fields.Str(
        data_key="data-agreement-id",
        required=False,
        description="The data agreement identifier",
        example=UUIDFour.EXAMPLE,
    )


# Handler class path for Data Agreement Termination Problem Report (data-agreement-termination/1.0/problem-report) message
DATA_AGREEMENT_TERMINATION_PROBLEM_REPORT_HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".data_agreement_termination_problem_report_handler.DataAgreementTerminationProblemReportHandler"
)


class DataAgreementTerminationProblemReportReason(str, Enum):
    """Supported reason codes."""

    # Trigger when data agreement signature verification fails.
    SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"

    # Trigger when data agreement is not found.
    DATA_AGREEMENT_NOT_FOUND = "data_agreement_not_found"

    # Trigger when principle (Data Subject) DID is invalid.
    PRINCIPLE_DID_INVALID = "principle_did_invalid"


class DataAgreementTerminationProblemReport(AgentMessage):
    """Base class representing a data agreement termination problem report message."""

    class Meta:
        """Data agreement termination problem report metadata."""

        handler_class = DATA_AGREEMENT_TERMINATION_PROBLEM_REPORT_HANDLER_CLASS
        message_type = DATA_AGREEMENT_TERMINATION_PROBLEM_REPORT
        schema_class = "DataAgreementTerminationProblemReportSchema"

    def __init__(
        self,
        *,
        problem_code: str = None,
        explain: str = None,
        from_did: str = None,
        to_did: str = None,
        created_time: str = None,
        data_agreement_id: str = None,
        **kwargs,
    ):
        """
        Initialize a DataAgreementTerminationProblemReport message instance.

        Args:
            explain: The localized error explanation
            problem_code: The standard error identifier
            from_did: Sender DID
            to_did: Receipient DID
            created_time: The timestamp of the message
            data_agreement_id: The data agreement identifier
        """
        super().__init__(**kwargs)
        self.explain = explain
        self.problem_code = problem_code
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time
        self.data_agreement_id = data_agreement_id


class DataAgreementTerminationProblemReportSchema(AgentMessageSchema):
    """
    Data agreement termination problem report schema.
    """

    class Meta:
        """Metadata for data agreement termination problem report schema."""

        model_class = DataAgreementTerminationProblemReport
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
            choices=[
                dapr.value for dapr in DataAgreementTerminationProblemReportReason
            ],
            error="Value {input} must be one of {choices}.",
        ),
        example=DataAgreementTerminationProblemReportReason.SIGNATURE_VERIFICATION_FAILED.value,
    )
    data_agreement_id = fields.Str(
        data_key="data-agreement-id",
        required=False,
        description="The data agreement identifier",
        example=UUIDFour.EXAMPLE,
    )
