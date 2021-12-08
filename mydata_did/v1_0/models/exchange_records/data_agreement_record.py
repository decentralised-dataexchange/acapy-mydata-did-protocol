from typing import Any

from marshmallow import fields, validate

from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from aries_cloudagent.messaging.valid import UUIDFour

class DataAgreementV1Record(BaseExchangeRecord):
    """
    DataAgreementV1Record model class for serialisation/deserialisation of data agreement records to and from wallet.
    Data agreement schema will be version 1.0.
    """
    class Meta:
        # Data Agreement Record schema (version 1.0)
        schema_class = "DataAgreementV1RecordSchema"

    # Wallet record type
    RECORD_TYPE = "data_agreement_record"

    # Wallet record identifier field
    RECORD_ID_NAME = "data_agreement_record_id"

    # Webhook topic name for this record type
    WEBHOOK_TOPIC = None

    # Wallet record tags used for filtering
    # Note: These are not tags for the ledger, but rather tags for the wallet
    #      to group records.
    TAG_NAMES = {
        "~method_of_use", 
        "~data_agreement_id", 
        "~published_flag", 
        "~delete_flag",
        "~schema_id",
        "~cred_def_id",
    }

    # State of the data agreement.
    # Only one possible value at this stage of the DA - preparation
    STATE_PREPARATION = "PREPARATION"

    METHOD_OF_USE_DATA_SOURCE = "data-source"
    METHOD_OF_USE_DATA_USING_SERVICE = "data-using-service"

    def __init__(
        self,
        *,
        data_agreement_record_id: str = None,
        data_agreement_id: str = None,
        state: str = None,
        method_of_use: str = None,
        data_agreement: dict = None,
        published_flag: str = "False",
        delete_flag: str = "False",
        schema_id: str = None,
        cred_def_id: str = None,
        data_agreement_proof_presentation_request: dict = None,
        **kwargs
    ):
        """
        Initialise a new DataAgreementRecordV1 instance.

        Args:
            data_agreement_id: The unique identifier for the data agreement.
            state: The state of the data agreement.
            method_of_use: The method of use for the data agreement.
            data_agreement: The data agreement.
            kwargs: Any other parameters.
        """
        super().__init__(data_agreement_record_id, state, **kwargs)
        self.method_of_use = method_of_use
        self.state = state
        self.data_agreement = data_agreement
        self.data_agreement_id = data_agreement_id
        self.published_flag = published_flag
        self.delete_flag = delete_flag
        self.schema_id = schema_id
        self.cred_def_id = cred_def_id
        self.data_agreement_proof_presentation_request = data_agreement_proof_presentation_request

    @property
    def data_agreement_record_id(self) -> str:
        """Accessor for data_agreement_record_id."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this transaction record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "state",
                "method_of_use",
                "data_agreement",
                "data_agreement_id",
                "published_flag",
                "delete_flag",
                "schema_id",
                "cred_def_id",
                "data_agreement_proof_presentation_request",
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class DataAgreementV1RecordSchema(BaseExchangeSchema):

    class Meta:
        """DataAgreementRecordV1Schema metadata."""

        # Model class
        model_class = DataAgreementV1Record

    # Data agreement record identifier
    data_agreement_record_id = fields.Str(
        required=True,
        description="Data Agreement Record identifier",
        example=UUIDFour.EXAMPLE
    )

    # Data agreement identifier
    data_agreement_id = fields.Str(
        required=True,
        description="The unique identifier for the data agreement.",
        example=UUIDFour.EXAMPLE
    )

    # State of the data agreement.
    state = fields.Str(
        required=True,
        description="The state of the data agreement.",
        example=DataAgreementV1Record.STATE_PREPARATION,
        validate=validate.OneOf(
            [
                DataAgreementV1Record.STATE_PREPARATION,
            ]
        )
    )

    # Method of use for the data agreement.
    method_of_use = fields.Str(
        required=True,
        description="The method of use for the data agreement.",
        example="data-source",
        validate=validate.OneOf(
            [
                DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE,
                DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE,
            ]
        )
    )

    # Data agreement
    data_agreement = fields.Dict(
        required=True,
        description="The data agreement.",
    )

    # Production flag
    published_flag = fields.Str(
        required=True,
        description="The production flag.",
        example="False",
        validate=validate.OneOf(
            [
                "True",
                "False",
            ]
        )
    )

    # Delete flag
    delete_flag = fields.Str(
        required=True,
        description="The delete flag.",
        example="False",
        validate=validate.OneOf(
            [
                "True",
                "False",
            ]
        )
    )

    # Schema identifier
    schema_id = fields.Str(
        required=True,
        description="The schema identifier.",
        example="WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0"
    )

    # Credential definition identifier
    cred_def_id = fields.Str(
        required=True,
        description="The credential definition identifier.",
        example="WgWxqztrNooG92RXvxSTWv:3:CL:20:tag"
    )

    # Data agreement proof presentation request
    data_agreement_proof_presentation_request = fields.Dict(
        required=True,
        description="The data agreement proof presentation request.",
    )
