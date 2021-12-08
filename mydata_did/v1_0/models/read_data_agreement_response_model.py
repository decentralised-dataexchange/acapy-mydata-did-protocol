import datetime

from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields, EXCLUDE
from marshmallow.exceptions import ValidationError
from typing import List

from ..utils.regex import MYDATA_DID
from .data_agreement_instance_model import DataAgreementInstanceSchema, DataAgreementInstance

class ReadDataAgreementResponseBody(BaseModel):
    """ReadDataAgreementResponseBody model class"""

    class Meta:
        """ReadDataAgreementResponseBody metadata"""
        schema_class = "ReadDataAgreementResponseBodySchema"

    def __init__(
        self,
        *,
        data_agreement :DataAgreementInstance = None,
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