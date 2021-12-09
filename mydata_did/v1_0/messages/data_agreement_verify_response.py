from marshmallow import EXCLUDE, fields

from aries_cloudagent.messaging.ack.message import Ack, AckSchema

from ..message_types import DATA_AGREEMENT_PROOFS_VERIFY_RESPONSE, PROTOCOL_PACKAGE

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.data_agreement_verify_response_handler.DataAgreementVerifyResponseHandler"
)


class DataAgreementVerifyResponse(Ack):
    """Base class representing data agreement verify response."""

    class Meta:
        """DataAgreementVerifyResponse metadata."""

        handler_class = HANDLER_CLASS
        message_type = DATA_AGREEMENT_PROOFS_VERIFY_RESPONSE
        schema_class = "DataAgreementVerifyResponseSchema"

    def __init__(self, status: str = None, explain: str = None, **kwargs):
        """
        Initialize data agreement verify response instance.

        Args:
            status: Status (default OK)

        """
        super().__init__(status, **kwargs)
        self.explain = explain


class DataAgreementVerifyResponseSchema(AckSchema):
    """Schema for DataAgreementVerifyResponse class."""

    class Meta:
        """DataAgreementVerifyResponse schema metadata."""

        model_class = DataAgreementVerifyResponse
        unknown = EXCLUDE
    
    explain = fields.Str(
        required=False,
        description="Localized error explanation",
        example="Signature verification failed.",
    )
