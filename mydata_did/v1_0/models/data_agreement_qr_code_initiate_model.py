from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields


class DataAgreementQrCodeInitiateBody(BaseModel):
    """Data Agreement Qr code initiate body"""

    class Meta:
        """Data Agreement Qr code initiate Body metadata"""

        schema_class = "DataAgreementQrCodeInitiateBodySchema"

    def __init__(self, *, qr_id: str = None, **kwargs):
        """Data Agreement Qr Code Initiate Body init"""

        super().__init__(**kwargs)

        # Set attributes
        self.qr_id = qr_id


class DataAgreementQrCodeInitiateBodySchema(BaseModelSchema):
    """Data Agreement Qr Code Initiate Body schema"""

    class Meta:
        """Data Agreement Qr Code Initiate Body schema metadata"""

        model_class = DataAgreementQrCodeInitiateBody

    # Data agreement id
    qr_id = fields.Str(example=UUIDFour.EXAMPLE, description="Qr code identifier")
