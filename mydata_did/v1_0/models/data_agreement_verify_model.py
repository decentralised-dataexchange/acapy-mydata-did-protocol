import datetime

from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields, EXCLUDE

from ..utils.regex import MYDATA_DID
from .data_agreement_instance_model import DataAgreementInstanceSchema, DataAgreementInstance

class DataAgreementVerifyBody(BaseModel):
    """DataAgreementVerifyBody model class"""

    class Meta:
        """DataAgreementVerifyBody metadata"""
        schema_class = "DataAgreementVerifyBodySchema"

    def __init__(
        self,
        *,
        data_agreement :DataAgreementInstance = None,
        **kwargs,
    ):
        """
        Initialize DataAgreementVerifyBody model

        :param data_agreement: Data Agreement
        :param kwargs: kwargs
        """
        super().__init__(**kwargs)
        self.data_agreement = data_agreement


class DataAgreementVerifyBodySchema(BaseModelSchema):
    """DataAgreementVerifyBody schema class"""

    class Meta:
        """DataAgreementVerifyBodySchema metadata"""
        model_class = DataAgreementVerifyBody
        unknown = EXCLUDE

    data_agreement = fields.Nested(DataAgreementInstanceSchema())