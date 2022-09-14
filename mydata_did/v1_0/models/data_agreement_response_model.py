from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields


class DataAgreementResponseBody(BaseModel):
    """
    Data agreement response body model class
    """

    class Meta:
        schema_class = "DataAgreementResponseBodySchema"

    def __init__(self, *, data_agreement_id: str, **kwargs):
        super().__init__(**kwargs)
        self.data_agreement_id = data_agreement_id


class DataAgreementResponseBodySchema(BaseModelSchema):
    """
    Data agreement response schema class
    """

    class Meta:
        model_class = DataAgreementResponseBody
        unknown = EXCLUDE

    data_agreement_id = fields.Str(
        data_key="data_agreement_id",
        example="45988dd2-62b9-4ede-8189-fb99c64b42d1",
        description="Data agreement identifier",
    )
