from enum import Enum
from marshmallow import EXCLUDE, fields, validate

from aries_cloudagent.messaging.agent_message import AgentMessage, AgentMessageSchema
from aries_cloudagent.messaging.valid import UUIDFour

from ..message_types import (
    PROTOCOL_PACKAGE,
    JSON_LD_PROBLEM_REPORT
)
from ..utils.regex import MYDATA_DID

# Handler class path for JSONLD Problem Report (json-ld/1.0/problem-report) message
JSON_LD_PROBLEM_REPORT_HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers"
    ".json_ld_problem_report_handler.JSONLDProblemReportHandler"
)


class JSONLDProblemReportReason(str, Enum):
    """Supported reason codes."""

    # Failed to generate processed data due to invalid input
    INVALID_INPUT = "invalid_input"


class JSONLDProblemReport(AgentMessage):
    """Base class representing a JSON-LD problem report message."""

    class Meta:
        """JSON-LD problem report metadata."""

        handler_class = JSON_LD_PROBLEM_REPORT_HANDLER_CLASS
        message_type = JSON_LD_PROBLEM_REPORT
        schema_class = "JSONLDProblemReportSchema"

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
        Initialize a JSONLDProblemReport message instance.

        Args:
            explain: The localized error explanation
            problem_code: The standard error identifier
            from_did: Sender DID
            to_did: Receipient DID
            created_time: The timestamp of the message
        """
        super().__init__(**kwargs)
        self.explain = explain
        self.problem_code = problem_code
        self.from_did = from_did
        self.to_did = to_did
        self.created_time = created_time


class JSONLDProblemReportSchema(AgentMessageSchema):
    """
    JSON-LD problem report schema.
    """
    class Meta:
        """Metadata for JSON-LD problem report schema."""

        model_class = JSONLDProblemReport
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
                dapr.value for dapr in JSONLDProblemReportReason],
            error="Value {input} must be one of {choices}.",
        ),
        example=JSONLDProblemReportReason.INVALID_INPUT.value,
    )