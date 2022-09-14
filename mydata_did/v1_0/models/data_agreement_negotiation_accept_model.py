from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields
from mydata_did.v1_0.models.data_agreement_negotiation_offer_model import (
    DataAgreementEvent,
    DataAgreementEventSchema,
    DataAgreementProof,
    DataAgreementProofSchema,
)


class DataAgreementNegotiationAcceptBody(BaseModel):
    """Data Agreement Negotiation Accept Body"""

    class Meta:
        """Data Agreement Negotiation Accept Body metadata"""

        schema_class = "DataAgreementNegotiationAcceptBodySchema"

    def __init__(
        self,
        *,
        data_agreement_id: str = None,
        event: DataAgreementEvent = None,
        proof: DataAgreementProof = None,
        **kwargs
    ):
        """Data Agreement Negotiation Accept Body init"""

        super().__init__(**kwargs)

        # Set attributes
        self.data_agreement_id = data_agreement_id
        self.event = event
        self.proof = proof


class DataAgreementNegotiationAcceptBodySchema(BaseModelSchema):
    """Data Agreement Negotiation Accept Body schema"""

    class Meta:
        """Data Agreement Negotiation Accept Body schema metadata"""

        model_class = DataAgreementNegotiationAcceptBody

    # Data agreement id
    data_agreement_id = fields.Str(
        data_key="id", example=UUIDFour.EXAMPLE, description="Data agreement identifier"
    )

    # Data agreement events
    event = fields.Nested(DataAgreementEventSchema)

    # Data agreement proof
    proof = fields.Nested(DataAgreementProofSchema)
