from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields


class JSONLDProcessedResponseBody(BaseModel):
    """json-ld/1.0/processed-data-response message body"""

    class Meta:
        """json-ld/1.0/processed-data-response message body metadata"""

        schema_class = "JSONLDProcessedResponseBodySchema"

    def __init__(
        self, *, framed_base64: str = None, combined_hash_base64: str = None, **kwargs
    ):
        """json-ld/1.0/processed-data-response message body init"""

        super().__init__(**kwargs)

        # Set attributes
        self.framed_base64 = framed_base64
        self.combined_hash_base64 = combined_hash_base64


class JSONLDProcessedResponseBodySchema(BaseModelSchema):
    """json-ld/1.0/processed-data-response message body schema"""

    class Meta:
        """json-ld/1.0/processed-data-response message body schema metadata"""

        model_class = JSONLDProcessedResponseBody

    # JSON-LD framed data
    framed_base64 = fields.Str(
        description="JSON-LD framed data",
    )

    # Combined hash ( JSON-LD data + signature options )
    combined_hash_base64 = fields.Str(
        description="Combined hash ( JSON-LD data + signature options )",
    )
