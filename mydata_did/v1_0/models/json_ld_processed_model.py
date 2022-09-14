from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields


class JSONLDProcessedBody(BaseModel):
    """JSONLD processed message body"""

    class Meta:
        """JSONLD processed message body metadata"""

        schema_class = "JSONLDProcessedBodySchema"

    def __init__(
        self, *, data_base64: str = None, signature_options_base64: str = None, **kwargs
    ):
        """JSONLD processed message body init"""

        super().__init__(**kwargs)

        # Set attributes
        self.data_base64 = data_base64
        self.signature_options_base64 = signature_options_base64


class JSONLDProcessedBodySchema(BaseModelSchema):
    """JSONLD processed message body schema"""

    class Meta:
        """JSONLD processed message body schema metadata"""

        model_class = JSONLDProcessedBody

    # JSON-LD input data
    data_base64 = fields.Str(
        description="JSON-LD input data",
    )

    # Signature options
    signature_options_base64 = fields.Str(
        description="Signature options",
    )
