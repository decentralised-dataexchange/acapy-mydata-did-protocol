import typing
from typing import Any

from aries_cloudagent.messaging.models.base_record import (
    BaseExchangeRecord,
    BaseExchangeSchema,
)
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields


class DataAgreementCRUDDIDCommTransaction(BaseExchangeRecord):
    """
    Transaction record model class for Data Agreement CRUD didcomm message lifecycle.
    for e.g. create-data-agreement and create-data-agreement-response messages are part of
    create-data-agreement didcomm message lifecycle.

    Model class will create a transaction record adhering to the schema specified and
    store the record in the wallet.

    Each transaction record will have 2 tags: thread_id and message_type.

    1. thread_id - identifier of the initial message that triggered the transaction.
    2. message_type - identifier of the message family that triggered the transaction
                        for .e.g. create-data-agreement
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementCRUDDIDCommTransactionSchema"

    RECORD_TYPE = "data_agreement_crud_didcomm_transaction"
    RECORD_ID_NAME = "da_crud_didcomm_tx_id"
    WEBHOOK_TOPIC = None
    TAG_NAMES = {"~thread_id", "~message_type", "~connection_id"}

    # Message family for the transaction record
    # Create Data Agreement message family
    MESSAGE_TYPE_CREATE_DATA_AGREEMENT = "create-data-agreement"
    # Read Data Agreement message family
    MESSAGE_TYPE_READ_DATA_AGREEMENT = "read-data-agreement"
    # Update Data Agreement message family
    MESSAGE_TYPE_UPDATE_DATA_AGREEMENT = "update-data-agreement"
    # Delete Data Agreement message family
    MESSAGE_TYPE_DELETE_DATA_AGREEMENT = "delete-data-agreement"

    def __init__(
        self,
        *,
        da_crud_didcomm_tx_id: str = None,
        thread_id: str = None,
        message_type: str = None,
        messages_list: typing.List[dict] = None,
        connection_id: str = None,
        **kwargs
    ):
        super().__init__(da_crud_didcomm_tx_id, **kwargs)
        self.thread_id = thread_id
        self.message_type = message_type
        self.messages_list = messages_list
        self.connection_id = connection_id

    @property
    def da_crud_didcomm_tx_id(self) -> str:
        """
        Returns transaction record identifier.
        """
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this transaction record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "thread_id",
                "message_type",
                "messages_list",
                "connection_id",
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class DataAgreementCRUDDIDCommTransactionSchema(BaseExchangeSchema):
    class Meta:
        # Model class
        model_class = DataAgreementCRUDDIDCommTransaction

    # Transaction record id
    da_crud_didcomm_tx_id = fields.Str(
        required=True,
        description="Transaction record id",
        example=UUIDFour.EXAMPLE,
    )

    # Parent message id of the transaction record
    thread_id = fields.Str(
        required=False,
        description="Parent message identifier",
        example=UUIDFour.EXAMPLE,
    )
    # Message type of the transaction record
    message_type = fields.Str(
        required=False,
        description="DIDComm message family",
        example="create-data-agreement",
    )
    # List of messages in the transaction record
    messages_list = fields.List(
        fields.Dict(), required=False, description="Messages list"
    )

    # Connection identifier
    connection_id = fields.Str(
        required=False,
        description="Connection identifier",
        example=UUIDFour.EXAMPLE,
    )
