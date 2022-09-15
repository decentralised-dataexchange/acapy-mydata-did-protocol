import typing

from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields


class FPRControllerDetailsModel(BaseModel):
    class Meta:
        schema_class = "FPRControllerDetailsModelSchema"

    def __init__(
        self,
        organisation_did: str = None,
        organisation_name: str = None,
        cover_image_url: str = None,
        logo_image_url: str = None,
        location: str = None,
        organisation_type: str = None,
        description: str = None,
        policy_url: str = None,
        eula_url: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)

        self.organisation_did = organisation_did
        self.organisation_name = organisation_name
        self.cover_image_url = cover_image_url
        self.logo_image_url = logo_image_url
        self.location = location
        self.organisation_type = organisation_type
        self.description = description
        self.policy_url = policy_url
        self.eula_url = eula_url


class FPRControllerDetailsModelSchema(BaseModelSchema):
    class Meta:
        model_class = FPRControllerDetailsModel
        unknown = EXCLUDE

    organisation_did = fields.Str(required=False)
    organisation_name = fields.Str(required=False)
    cover_image_url = fields.Str(required=False)
    logo_image_url = fields.Str(required=False)
    location = fields.Str(required=False)
    organisation_type = fields.Str(required=False)
    description = fields.Str(required=False)
    policy_url = fields.Str(required=False)
    eula_url = fields.Str(required=False)


class FPRDUSModel(BaseModel):
    class Meta:
        schema_class = "FPRDUSModelSchema"

    def __init__(
        self,
        controller_details: FPRControllerDetailsModel = None,
        dda_instance_id: str = None,
        dda_instance_permission_state: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)

        self.controller_details = controller_details
        self.dda_instance_id = dda_instance_id
        self.dda_instance_permission_state = dda_instance_permission_state


class FPRDUSModelSchema(BaseModelSchema):
    class Meta:
        model_class = FPRDUSModel
        unknown = EXCLUDE

    controller_details = fields.Nested(FPRControllerDetailsModelSchema, required=False)
    dda_instance_id = fields.Str(required=False)
    dda_instance_permission_state = fields.Str(required=False)


class FPRPrefsModel(BaseModel):
    class Meta:
        schema_class = "FPRPrefsModelSchema"

    def __init__(
        self,
        instance_id: str = None,
        instance_permission_state: str = None,
        dus: typing.List[FPRDUSModel] = None,
        sector: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)

        # Set attributes
        self.instance_id = instance_id
        self.instance_permission_state = instance_permission_state
        self.dus = dus
        self.sector = sector


class FPRPrefsModelSchema(BaseModelSchema):
    class Meta:
        model_class = FPRPrefsModel

    instance_id = fields.Str(required=False)
    instance_permission_state = fields.Str(required=False)
    sector = fields.Str(required=False)
    dus = fields.List(fields.Nested(FPRDUSModelSchema), required=False)


class FetchPreferencesResponseBody(BaseModel):
    class Meta:
        schema_class = "FetchPreferencesResponseBodySchema"

    def __init__(
        self,
        *,
        prefs: typing.List[FPRPrefsModel] = None,
        sectors: typing.List[str] = None,
        **kwargs
    ):
        super().__init__(**kwargs)

        # Set attributes
        self.prefs = prefs
        self.sectors = sectors


class FetchPreferencesResponseBodySchema(BaseModelSchema):
    class Meta:
        model_class = FetchPreferencesResponseBody

    prefs = fields.List(fields.Nested(FPRPrefsModelSchema), required=False)
    sectors = fields.List(fields.Str, required=False)
