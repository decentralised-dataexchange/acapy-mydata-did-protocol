from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import fields


class ExistingConnectionsBody(BaseModel):
    """Existing connections message body"""

    class Meta:
        """Existing connection message body metadata"""

        schema_class = "ExistingConnectionsBodySchema"

    def __init__(self, *, theirdid: str = None, **kwargs):
        """ExistingConnectionsBody init"""

        super().__init__(**kwargs)

        # Set attributes
        self.theirdid = theirdid


class ExistingConnectionsBodySchema(BaseModelSchema):
    """Existing connections message body schema"""

    class Meta:
        """ExistingConnectionsBodySchema metadata"""

        model_class = ExistingConnectionsBody

    # Pairwise DID of the existing connection.
    theirdid = fields.Str()
