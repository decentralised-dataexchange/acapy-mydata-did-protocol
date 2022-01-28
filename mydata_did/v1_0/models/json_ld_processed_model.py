from marshmallow import fields
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour


class JSONLDProcessedBody(BaseModel):
    """json-ld/1.0/processed-data message body"""

    class Meta:
        """json-ld/1.0/processed-data message body metadata"""

        schema_class = "JSONLDProcessedBodySchema"

    def __init__(
        self,
        *,
        data_base64: str = None,
        signature_options_base64: str = None,
        proof_chain: bool = False,
        **kwargs
    ):
        """json-ld/1.0/processed-data message body init"""

        super().__init__(**kwargs)

        # Set attributes
        self.data_base64 = data_base64
        self.signature_options_base64 = signature_options_base64
        self.proof_chain = proof_chain


class JSONLDProcessedBodySchema(BaseModelSchema):
    """json-ld/1.0/processed-data message body schema"""

    class Meta:
        """json-ld/1.0/processed-data message body schema metadata"""

        model_class = JSONLDProcessedBody

    # JSON-LD input data
    data_base64 = fields.Str(
        description="JSON-LD input data",
    )

    # Signature options
    signature_options_base64 = fields.Str(
        description="Signature options",
    )

    # Proof chain
    proof_chain = fields.Boolean(
        description="Proof chain",
    )
