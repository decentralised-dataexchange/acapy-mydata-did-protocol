from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields, EXCLUDE
from marshmallow.exceptions import ValidationError

from ..utils.diddoc import DIDDoc

class DIDDocWrapper(fields.Field):
    """Field that loads and serializes DIDDoc."""

    def _serialize(self, value, attr, obj, **kwargs):
        """
        Serialize the DIDDoc.

        Args:
            value: The value to serialize

        Returns:
            The serialized DIDDoc

        """
        return value.serialize()

    def _deserialize(self, value, attr, data, **kwargs):
        """
        Deserialize a value into a DIDDoc.

        Args:
            value: The value to deserialize

        Returns:
            The deserialized value

        """
        return DIDDoc.deserialize(value)
    
    def _validate(self, value: DIDDoc):
        if not value.validate():
            raise ValidationError("MyData DIDDoc is not valid.")

class MyDataDIDBody(BaseModel):
    class Meta:
        schema_class = "MyDataDIDBodySchema"
    
    def __init__(self, *, did_doc: DIDDoc, **kwargs):
        super().__init__(**kwargs)
        self.did_doc = did_doc

class MyDataDIDBodySchema(BaseModelSchema):
    class Meta:
        model_class = MyDataDIDBody
        unknown = EXCLUDE
    
    did_doc = DIDDocWrapper(
        data_key="did",
        required=False
    )


class MyDataDIDBodyResponse(BaseModel):
    class Meta:
        schema_class = "MyDataDIDBodyResponseSchema"
    
    def __init__(self, *, did_doc: DIDDoc, version: str, **kwargs):
        super().__init__(**kwargs)
        self.did_doc = did_doc
        self.version = version

class MyDataDIDBodyResponseSchema(BaseModelSchema):
    class Meta:
        model_class = MyDataDIDBodyResponse
        unknown = EXCLUDE
    
    did_doc = DIDDocWrapper(
        data_key="did",
        required=False
    )
    version = fields.Str(data_key="version")