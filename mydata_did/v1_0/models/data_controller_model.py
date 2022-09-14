from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields


class DataController(BaseModel):
    """
    Data controller model class
    """

    class Meta:
        schema_class = "DataControllerSchema"

    def __init__(
        self,
        *,
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


class DataControllerSchema(BaseModelSchema):
    """
    Data controller schema class
    """

    class Meta:
        model_class = DataController
        unknown = EXCLUDE

    organisation_did = fields.Str()
    organisation_name = fields.Str()
    cover_image_url = fields.Str()
    logo_image_url = fields.Str()
    location = fields.Str()
    organisation_type = fields.Str()
    description = fields.Str()
    policy_url = fields.Str()
    eula_url = fields.Str()
