from os import environ
from typing import Any

from marshmallow import fields, validate

from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from aries_cloudagent.messaging.valid import UUIDFour


class DataAgreementCRUDDIDCommTransaction(BaseExchangeRecord):
    """
    Transaction record model class for Data Agreement CRUD didcomm message lifecycle.
    for e.g. create-data-agreement and create-data-agreement-response messages are part of
    create-data-agreement didcomm message lifecycle.

    Model class will create a transaction record adhering to the schema specified and
    store the record in the wallet.

    Each transaction record will have 2 tags: parent_message_id and message_family.

    1. parent_message_id - identifier of the initial message that triggered the transaction.
    2. message_family - identifier of the message family that triggered the transaction 
                        for .e.g. create-data-agreement
    """
    class Meta:
        # Schema class
        schema_class = "DataAgreementCRUDDIDCommTransactionSchema"

    RECORD_TYPE = "data_agreement_crud_didcomm_transaction"
    RECORD_ID_NAME = "da_crud_didcomm_tx_id"
    WEBHOOK_TOPIC = None
    TAG_NAMES = {"~parent_message_id", "~message_family"}

    # Message family for the transaction record
    # Create Data Agreement message family
    MESSAGE_FAMILY_CREATE_DATA_AGREEMENT = "create-data-agreement"
    # Read Data Agreement message family
    MESSAGE_FAMILY_READ_DATA_AGREEMENT = "read-data-agreement"
    # Update Data Agreement message family
    MESSAGE_FAMILY_UPDATE_DATA_AGREEMENT = "update-data-agreement"
    # Delete Data Agreement message family
    MESSAGE_FAMILY_DELETE_DATA_AGREEMENT = "delete-data-agreement"

    def __init__(
        self,
        *,
        da_crud_didcomm_tx_id: str = None,
        parent_message_id: str = None,
        message_family: str = None,
        messages_list: dict = None,
        **kwargs
    ):
        super().__init__(da_crud_didcomm_tx_id, **kwargs)
        self.parent_message_id = parent_message_id
        self.message_family = message_family
        self.messages_list = messages_list

    @property
    def da_crud_didcomm_tx_id(self) -> str:
        """
        Returns the parent message id of the transaction record.
        """
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this transaction record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "parent_message_id",
                "message_family",
                "messages_list",
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
    parent_message_id = fields.Str(
        required=False,
        description="Parent message identifier",
        example=UUIDFour.EXAMPLE,
    )
    # Message family of the transaction record
    message_family = fields.Str(
        required=False,
        description="DIDComm message family",
        example="create-data-agreement",
    )
    # List of messages in the transaction record
    messages_list = fields.List(fields.Dict(), required=False, description="Messages list")
