from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields


class DAPermissionsBodyModel(BaseModel):
    class Meta:
        schema_class = "DAPermissionsBodyModelSchema"

    def __init__(self, *, instance_id: str = None, state: str = None, **kwargs):

        super().__init__(**kwargs)

        # Set attributes
        self.instance_id = instance_id
        self.state = state


class DAPermissionsBodyModelSchema(BaseModelSchema):
    class Meta:
        model_class = DAPermissionsBodyModel

    instance_id = fields.Str()
    state = fields.Str()
