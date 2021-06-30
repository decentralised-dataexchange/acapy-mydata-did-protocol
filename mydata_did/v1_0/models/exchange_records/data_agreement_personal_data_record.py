from os import environ
from typing import Any

from marshmallow import fields, validate

from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from aries_cloudagent.messaging.valid import UUIDFour

from ..data_agreement_model import DataAgreementPersonalData, DataAgreementPersonalDataSchema

class DataAgreementPersonalDataRecord(BaseExchangeRecord):
    """
    DataAgreementPersonalDataRecord model class for serialisation/deserialisation of data agreement personal data records to/from wallet.
    """
    class Meta:
        # Data Agreement Personal Data Record schema class
        schema_class = "DataAgreementPersonalDataRecordSchema"

    # Wallet record type
    RECORD_TYPE = "data_agreement_personal_data_record"

    # Wallet record identifier field
    RECORD_ID_NAME = "data_agreement_personal_data_record_id"

    # Webhook topic name for this record type
    WEBHOOK_TOPIC = None

    # Wallet record tags used for filtering
    # Note: These are not tags for the ledger, but rather tags for the wallet
    #      to group records.
    TAG_NAMES = {"~attribute_category", "~attribute_sensitive"}

    def __init__(
        self,
        *,
        data_agreement_personal_data_record_id: str = None,
        attribute_name: str = None,
        attribute_category: str = "Other",
        attribute_sensitive: str = "True",
        attribute_description: str = "Nil",
        state: str = None,
        **kwargs
    ):
        """
        Initialise a new DataAgreementPersonalDataRecord instance.

        Args:
            data_agreement_personal_data_record_id: The unique identifier for the data agreement personal data record.
            attribute_name: The name of the attribute.
            attribute_category: The category of the attribute.
            attribute_sensitive: The sensitive flag of the attribute.
            state: The state of the data agreement personal data record.
        """
        super().__init__(data_agreement_personal_data_record_id, state, **kwargs)
        self.state = state
        self.attribute_name = attribute_name
        self.attribute_category = attribute_category
        self.attribute_sensitive = attribute_sensitive
        self.attribute_description = attribute_description

    @property
    def data_agreement_personal_data_record_id(self) -> str:
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
    

    data_agreement_personal_data_record_id = fields.Str(
        required=True,
        example=UUIDFour.EXAMPLE
    )

    attribute_name = fields.Str(
        required=True,
        description="The name of the attribute.",
        example="name"
    )

    attribute_description = fields.Str(
        required=True,
        description="The description of the attribute.",
        example="Name of the customer"
    )

    attribute_category = fields.Str(
        required=True,
        description="The category of the attribute.",
        example="personal"
    )


    attribute_sensitive = fields.Str(
        required=True,
        description="The sensitive flag of the attribute.",
        example="True"
    )


