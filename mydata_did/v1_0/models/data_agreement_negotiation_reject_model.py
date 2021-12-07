from marshmallow import fields
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour

from .data_agreement_negotiation_offer_model import (
    DataAgreementProof,
    DataAgreementProofSchema,
    DataAgreementEvent,
    DataAgreementEventSchema
)


class DataAgreementNegotiationRejectBody(BaseModel):
    """Data Agreement Negotiation Reject Body"""

    class Meta:
        """Data Agreement Negotiation Reject Body metadata"""

        schema_class = "DataAgreementNegotiationRejectBodySchema"

    def __init__(
        self,
        *,
        data_agreement_id: str = None,
        event: DataAgreementEvent = None,
        proof: DataAgreementProof = None,
        **kwargs
    ):
        """Data Agreement Negotiation Reject Body init"""

        super().__init__(**kwargs)

        # Set attributes
        self.data_agreement_id = data_agreement_id
        self.event = event
        self.proof = proof


class DataAgreementNegotiationRejectBodySchema(BaseModelSchema):
    """Data Agreement Negotiation Reject Body schema"""

    class Meta:
        """Data Agreement Negotiation Reject Body schema metadata"""

        model_class = DataAgreementNegotiationRejectBody

    # Data agreement id
    data_agreement_id = fields.Str(
        data_key="id",
        example=UUIDFour.EXAMPLE,
        description="Data agreement identifier"
    )

    # Data agreement events
    event = fields.Nested(DataAgreementEventSchema)

    # Data agreement proof
    proof = fields.Nested(DataAgreementProofSchema)
