from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields


class ReadDataAgreementBody(BaseModel):
    """
    Read data agreement body model class
    """

    class Meta:
        schema_class = "ReadDataAgreementBodySchema"

    def __init__(self, *, data_agreement_id: str, **kwargs):
        super().__init__(**kwargs)
        self.data_agreement_id = data_agreement_id


class ReadDataAgreementBodySchema(BaseModelSchema):
    """
    Read data agreement body schema class
    """

    class Meta:
        model_class = ReadDataAgreementBody
        unknown = EXCLUDE

    data_agreement_id = fields.Str(
        data_key="data_agreement_id",
        example="45988dd2-62b9-4ede-8189-fb99c64b42d1",
        description="Data agreement identifier",
    )
