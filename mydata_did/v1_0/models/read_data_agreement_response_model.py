from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields
from mydata_did.v1_0.models.data_agreement_instance_model import (
    DataAgreementInstance,
    DataAgreementInstanceSchema,
)


class ReadDataAgreementResponseBody(BaseModel):
    """ReadDataAgreementResponseBody model class"""

    class Meta:
        """ReadDataAgreementResponseBody metadata"""

        schema_class = "ReadDataAgreementResponseBodySchema"

    def __init__(
        self,
        *,
        data_agreement: DataAgreementInstance = None,
        **kwargs,
    ):
        """
        Initialize ReadDataAgreementResponseBody model

        :param data_agreement: Data Agreement
        :param kwargs: kwargs
        """
        super().__init__(**kwargs)
        self.data_agreement = data_agreement


class ReadDataAgreementResponseBodySchema(BaseModelSchema):
    """ReadDataAgreementResponseBody schema class"""

    class Meta:
        """ReadDataAgreementResponseBodySchema metadata"""

        model_class = ReadDataAgreementResponseBody
        unknown = EXCLUDE

    data_agreement = fields.Nested(DataAgreementInstanceSchema())
