import typing
from typing import Any

from aries_cloudagent.messaging.models.base_record import (
    BaseExchangeRecord,
    BaseExchangeSchema,
)
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields


class AuditorDIDCommTransactionRecord(BaseExchangeRecord):
    """
    AuditorDIDCommTransactionRecord

    Transaction record to keep track of audit operations against an Auditor.
    """

    class Meta:
        # Schema class
        schema_class = "AuditorDIDCommTransactionRecordSchema"

    # Record type
    RECORD_TYPE = "auditor_didcomm_transaction_record"

    # Wallet record identifier field
    RECORD_ID_NAME = "auditor_didcomm_transaction_record_id"

    # Webhook topic name for this record type
    WEBHOOK_TOPIC = None

    # Wallet record tags used for filtering
    TAG_NAMES = {"~thread_id", "~connection_id"}

    def __init__(
        self,
        *,
        auditor_didcomm_transaction_record_id: str = None,
        thread_id: str = None,
        messages_list: typing.List[dict] = None,
        connection_id: str = None,
        **kwargs
    ):
        super().__init__(auditor_didcomm_transaction_record_id, **kwargs)

        self.thread_id = thread_id
        self.messages_list = messages_list
        self.connection_id = connection_id

    @property
    def auditor_didcomm_transaction_record_id(self) -> str:
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
                "messages_list",
                "connection_id",
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class AuditorDIDCommTransactionRecordSchema(BaseExchangeSchema):
    """
    AuditorDIDCommTransactionRecordSchema

    Schema class for the AuditorDIDCommTransactionRecord class.
    """

    class Meta:
        # Model class
        model_class = AuditorDIDCommTransactionRecord

    # Wallet record identifier field
    auditor_didcomm_transaction_record_id = fields.Str(
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

    # List of messages for the transaction record
    messages_list = fields.List(
        fields.Dict(), required=False, description="Messages list"
    )

    # Connection identifier
    connection_id = fields.Str(
        required=False,
        description="Connection identifier",
        example=UUIDFour.EXAMPLE,
    )
