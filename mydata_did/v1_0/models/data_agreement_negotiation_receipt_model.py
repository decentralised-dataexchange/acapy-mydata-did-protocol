from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields


class DataAgreementNegotiationReceiptBody(BaseModel):
    """Data Agreement Negotiation Receipt Body"""

    class Meta:
        schema_class = "DataAgreementNegotiationReceiptBodySchema"

    def __init__(
        self,
        *,
        instance_id: str,
        blockchain_receipt: dict,
        blink: str,
        mydata_did: str,
        **kwargs
    ):
        super().__init__(**kwargs)

        # Set model attributes.
        self.blockchain_receipt = blockchain_receipt
        self.blink = blink
        self.mydata_did = mydata_did
        self.instance_id = instance_id


class DataAgreementNegotiationReceiptBodySchema(BaseModelSchema):
    """Data Agreement Negotiation Receipt Body schema"""

    class Meta:
        model_class = DataAgreementNegotiationReceiptBody

        # Unknown fields are excluded
        unknown = EXCLUDE

    instance_id = fields.Str()
    blockchain_receipt = fields.Dict()
    blink = fields.Str()
    mydata_did = fields.Str()
