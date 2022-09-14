import typing
from typing import Any

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.messaging.models.base_record import (
    BaseExchangeRecord,
    BaseExchangeSchema,
)
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields, validate
from mydata_did.v1_0.utils.util import bool_to_str


class DataAgreementV1Record(BaseExchangeRecord):
    """
    DataAgreementV1Record model class for serialisation/deserialisation of data agreement
    records to and from wallet.
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
        "~publish_flag",
        "~delete_flag",
        "~schema_id",
        "~cred_def_id",
        "~is_existing_schema",
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
        publish_flag: str = "false",
        delete_flag: str = "false",
        schema_id: str = None,
        cred_def_id: str = None,
        data_agreement_proof_presentation_request: dict = None,
        is_existing_schema: str = "false",
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
        self.publish_flag = publish_flag
        self.delete_flag = delete_flag
        self.schema_id = schema_id
        self.cred_def_id = cred_def_id
        self.data_agreement_proof_presentation_request = (
            data_agreement_proof_presentation_request
        )
        self.is_existing_schema = is_existing_schema

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
                "publish_flag",
                "delete_flag",
                "schema_id",
                "cred_def_id",
                "data_agreement_proof_presentation_request",
                "is_existing_schema",
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)

    @property
    def _publish_flag(self) -> bool:
        """Accessor for publish_flag."""
        return self.publish_flag == "true"

    @_publish_flag.setter
    def _publish_flag(self, value: bool) -> None:
        """Setter for publish_flag."""
        self.publish_flag = "true" if value else "false"

    @property
    def _delete_flag(self) -> bool:
        """Accessor for delete_flag."""
        return self.delete_flag == "true"

    @_delete_flag.setter
    def _delete_flag(self, value: bool) -> None:
        """Setter for delete_flag."""
        self.delete_flag = "true" if value else "false"

    @property
    def _is_existing_schema(self) -> bool:
        """Accessor for is_existing_schema."""
        return self.is_existing_schema == "true"

    @_is_existing_schema.setter
    def _is_existing_schema(self, value: bool) -> None:
        """Setter for is_existing_schema."""
        self.is_existing_schema = "true" if value else "false"

    @property
    def is_published(self) -> bool:
        """Check if data agreement record is published."""
        return True if self._publish_flag and not self._delete_flag else False

    @property
    def is_deleted(self) -> bool:
        """Check if data agreemnent is deleted."""
        return True if self._delete_flag and not self._publish_flag else False

    @property
    def is_draft(self) -> bool:
        """Check if data agreement is a draft."""
        return True if not self._publish_flag and not self._delete_flag else False

    @classmethod
    async def retrieve_non_deleted_data_agreement_by_id(
        cls,
        context: InjectionContext,
        data_agreement_id: str,
    ) -> "DataAgreementV1Record":
        """
        Retrieve a non-deleted data agreement record by its data agreement id.

        Args:
            context: The injection context to use.
            data_agreement_id: The data agreement id.

        Returns:
            The data agreement record.
        """

        tag_filter: dict = {
            "data_agreement_id": data_agreement_id,
            "delete_flag": bool_to_str(False),
        }
        post_filter: dict = None

        return await cls.retrieve_by_tag_filter(context, tag_filter, post_filter)

    @classmethod
    async def retrieve_all_non_deleted_data_agreements(
        cls,
        context: InjectionContext,
    ) -> typing.List["DataAgreementV1Record"]:
        """
        Retrieve all non-deleted data agreements.

        Args:
            context: The injection context to use.

        Returns:
            The data agreements.
        """

        tag_filter: dict = {"delete_flag": bool_to_str(False)}

        return await cls.query(
            context,
            tag_filter=tag_filter,
        )


class DataAgreementV1RecordSchema(BaseExchangeSchema):
    class Meta:
        """DataAgreementRecordV1Schema metadata."""

        # Model class
        model_class = DataAgreementV1Record

    # Data agreement record identifier
    data_agreement_record_id = fields.Str(
        required=True,
        description="Data Agreement Record identifier",
        example=UUIDFour.EXAMPLE,
    )

    # Data agreement identifier
    data_agreement_id = fields.Str(
        required=True,
        description="The unique identifier for the data agreement.",
        example=UUIDFour.EXAMPLE,
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
        ),
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
        ),
    )

    # Data agreement
    data_agreement = fields.Dict(
        required=True,
        description="The data agreement.",
    )

    # Production flag
    publish_flag = fields.Str(
        required=True,
        description="The production flag.",
        example="false",
        validate=validate.OneOf(
            [
                "true",
                "false",
            ]
        ),
    )

    # Delete flag
    delete_flag = fields.Str(
        required=True,
        description="The delete flag.",
        example="false",
        validate=validate.OneOf(
            [
                "true",
                "false",
            ]
        ),
    )

    # Schema identifier
    schema_id = fields.Str(
        required=True,
        description="The schema identifier.",
        example="WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0",
    )

    # Credential definition identifier
    cred_def_id = fields.Str(
        required=True,
        description="The credential definition identifier.",
        example="WgWxqztrNooG92RXvxSTWv:3:CL:20:tag",
    )

    # Data agreement proof presentation request
    data_agreement_proof_presentation_request = fields.Dict(
        required=True,
        description="The data agreement proof presentation request.",
    )

    is_existing_schema = fields.Str(
        required=True,
        description="Is existing schema.",
        example="false",
        validate=validate.OneOf(
            [
                "true",
                "false",
            ]
        ),
    )
