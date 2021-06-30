from os import environ
from typing import Any

from marshmallow import fields, validate

from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from aries_cloudagent.messaging.valid import UUIDFour


class MyDataDIDRegistryDIDCommTransactionRecord(BaseExchangeRecord):
    """
    MyDataDIDRegistryDIDCommTransactionRecord

    Transaction record to keep track of CRUD operations on DIDs against the MyData DID Registry.
    """

    class Meta:
        # Schema class
        schema_class = "MyDataDIDRegistryDIDCommTransactionRecordSchema"
    
    # Record type
    RECORD_TYPE = "mydata_did_registry_didcomm_transaction_record"

    # Wallet record identifier field
    RECORD_ID_NAME = "mydata_did_registry_didcomm_transaction_record_id"

    # Webhook topic name for this record type
    WEBHOOK_TOPIC = None

    # Wallet record tags used for filtering
    TAG_NAMES = {"~thread_id", "~message_type", "~connection_id"}

    # Message types for the transaction record

    # Create DID message type
    MESSAGE_TYPE_CREATE_DID = "create-did"

    # Read DID message type
    MESSAGE_TYPE_READ_DID = "read-did"

    # Delete DID message type
    MESSAGE_TYPE_DELETE_DID = "delete-did"

    def __init__(
        self,
        *,
        mydata_did_registry_didcomm_transaction_record_id: str = None,
        thread_id: str = None,
        message_type: str = None,
        messages_list: dict = None,
        connection_id: str = None,
        **kwargs
    ):
        super().__init__(mydata_did_registry_didcomm_transaction_record_id, **kwargs)

        self.thread_id = thread_id
        self.message_type = message_type
        self.messages_list = messages_list
        self.connection_id = connection_id

    @property
    def mydata_did_registry_didcomm_transaction_record_id(self) -> str:
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


class MyDataDIDRegistryDIDCommTransactionRecordSchema(BaseExchangeSchema):
    """
    MyDataDIDRegistryDIDCommTransactionRecordSchema

    Schema class for the MyDataDIDRegistryDIDCommTransactionRecord class.
    """

    class Meta:
        # Model class
        model_class = MyDataDIDRegistryDIDCommTransactionRecord
    

    # Wallet record identifier field
    mydata_did_registry_didcomm_transaction_record_id = fields.Str(
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
        description="Message family",
        example="create-did",
        validate=validate.OneOf(
            [
                MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_CREATE_DID,
                MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_READ_DID,
                MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_DELETE_DID,
            ]
        ),
    )

    # List of messages for the transaction record
    messages_list = fields.List(fields.Dict(), required=False, description="Messages list")

    # Connection identifier
    connection_id = fields.Str(
        required=False,
        description="Connection identifier",
        example=UUIDFour.EXAMPLE,
    )
