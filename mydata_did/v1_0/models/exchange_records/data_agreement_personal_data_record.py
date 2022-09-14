import typing
from typing import Any

from aries_cloudagent.messaging.models.base_record import (
    BaseExchangeRecord,
    BaseExchangeSchema,
)
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields
from mydata_did.v1_0.models.data_agreement_model import (
    DataAgreementPersonalDataRestrictionSchema,
)


class DataAgreementPersonalDataRecord(BaseExchangeRecord):
    """
    DataAgreementPersonalDataRecord model class for serialisation/deserialisation of
    data agreement personal data records to/from wallet.
    """

    class Meta:
        # Data Agreement Personal Data Record schema class
        schema_class = "DataAgreementPersonalDataRecordSchema"

    # Wallet record type
    RECORD_TYPE = "data_agreement_personal_data_record"

    # Wallet record identifier field
    RECORD_ID_NAME = "personal_data_id"

    # Webhook topic name for this record type
    WEBHOOK_TOPIC = None

    # Wallet record tags used for filtering
    # Note: These are not tags for the ledger, but rather tags for the wallet
    #      to group records.
    TAG_NAMES = {"~attribute_category", "~attribute_sensitive", "~da_template_id"}

    def __init__(
        self,
        *,
        personal_data_id: str = None,
        attribute_name: str = None,
        attribute_category: str = "Other",
        attribute_sensitive: str = "true",
        attribute_description: str = "Nil",
        state: str = None,
        restrictions: typing.List[dict] = None,
        da_template_id: str = None,
        da_template_version: int = None,
        **kwargs
    ):
        """
        Initialise a new DataAgreementPersonalDataRecord instance.

        Args:
            personal_data_id: The unique identifier for the data agreement personal data record.
            attribute_name: The name of the attribute.
            attribute_category: The category of the attribute.
            attribute_sensitive: The sensitive flag of the attribute.
            state: The state of the data agreement personal data record.
        """
        super().__init__(personal_data_id, state, **kwargs)
        self.state = state
        self.attribute_name = attribute_name
        self.attribute_category = attribute_category
        self.attribute_sensitive = attribute_sensitive
        self.attribute_description = attribute_description
        self.restrictions = restrictions
        self.da_template_id = da_template_id
        self.da_template_version = da_template_version

    @property
    def personal_data_id(self) -> str:
        """
        Get the data agreement personal data record identifier.

        Returns:
            The data agreement personal data record identifier.
        """
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this transaction record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "attribute_name",
                "attribute_category",
                "attribute_sensitive",
                "attribute_description",
                "restrictions",
                "da_template_id",
                "da_template_version",
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class DataAgreementPersonalDataRecordSchema(BaseExchangeSchema):
    class Meta:
        """DataAgreementPersonalDataRecordSchema metadata."""

        # Model class
        model_class = DataAgreementPersonalDataRecord

    personal_data_id = fields.Str(required=True, example=UUIDFour.EXAMPLE)

    attribute_name = fields.Str(
        required=True, description="The name of the attribute.", example="name"
    )

    attribute_description = fields.Str(
        required=True,
        description="The description of the attribute.",
        example="Name of the customer",
    )

    attribute_category = fields.Str(
        required=True, description="The category of the attribute.", example="personal"
    )

    attribute_sensitive = fields.Str(
        required=True,
        description="The sensitive flag of the attribute.",
        example="true",
    )

    restrictions = fields.List(
        fields.Nested(DataAgreementPersonalDataRestrictionSchema), required=False
    )

    da_template_id = fields.Str(
        required=True,
        description="The data agreement template identifier.",
        example=UUIDFour.EXAMPLE,
    )

    da_template_version = fields.Int(
        example=1, description="Data agreement template version"
    )
