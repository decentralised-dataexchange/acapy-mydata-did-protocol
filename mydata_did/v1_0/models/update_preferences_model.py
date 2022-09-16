from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields


class UpdatePreferencesBodyModel(BaseModel):
    class Meta:
        schema_class = "UpdatePreferencesBodyModelSchema"

    def __init__(
        self,
        *,
        dda_instance_id: str = None,
        da_instance_id: str = None,
        state: str = None,
        **kwargs
    ):

        super().__init__(**kwargs)

        # Set attributes
        self.dda_instance_id = dda_instance_id
        self.da_instance_id = da_instance_id
        self.state = state


class UpdatePreferencesBodyModelSchema(BaseModelSchema):
    class Meta:
        model_class = UpdatePreferencesBodyModel

    dda_instance_id = fields.Str()
    da_instance_id = fields.Str()
    state = fields.Str()
