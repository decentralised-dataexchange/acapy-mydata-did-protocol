from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields, validate


class DataAgreementContextDecorator(BaseModel):
    """
    Class representing a data agreement context decorator.
    """

    class Meta:
        """DataAgreementContextDecorator metadata."""

        schema_class = "DataAgreementContextDecoratorSchema"

    def __init__(self, *, message_type: str = None, message: dict = None, **kwargs):
        """
        Initialize a DataAgreementContextDecorator instance.

        Args:
            message_type: The type of the message.
            message: The message.
            kwargs: The keyword arguments

        """
        super().__init__(**kwargs)
        self.message_type = message_type
        self.message = message


class DataAgreementContextDecoratorSchema(BaseModelSchema):
    """
    DataAgreementContextDecorator schema.
    """

    class Meta:
        """DataAgreementContextDecoratorSchema metadata."""

        model_class = DataAgreementContextDecorator
        unknown = EXCLUDE

    message_type = fields.Str(
        required=False,
        description="The type of the message.",
        example="protocol",
        validate=validate.OneOf(["protocol", "non-protocol"]),
    )
    message = fields.Dict(
        required=False,
        description="The message.",
        example={"data_agreement_id": "12345678-1234-1234-1234-123456789012"},
    )
