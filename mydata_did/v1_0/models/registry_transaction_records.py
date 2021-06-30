from os import environ
from typing import Any

from marshmallow import fields, validate

from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from aries_cloudagent.messaging.valid import UUIDFour


class V10MyDataDIDRegistryTransaction(BaseExchangeRecord):
    class Meta:
        schema_class = "V10MyDataDIDRegistryTransactionSchema"

    RECORD_TYPE = "mydata_did_registry_transaction_v10"
    RECORD_ID_NAME = "mydata_did_registry_transaction_id"
    WEBHOOK_TOPIC = None
    TAG_NAMES = {"~thread_id", "~connection_id"}

    STATE_CREATE_DID_CREATE_REQUEST_SENT = "sent"
    STATE_CREATE_DID_CREATE_REQUEST_RECEIVED = "received"
    STATE_CREATE_DID_CREATE_FAILED = "failed"
    STATE_CREATE_DID_CREATE_SUCCESS = "success"

    RECORD_TYPE_CREATE = "create-did"
    RECORD_TYPE_READ = "read-did"
    RECORD_TYPE_DELETE = "delete-did"

    def __init__(
        self,
        *,
        mydata_did_registry_transaction_id: str = None,
        thread_id: str = None,
        connection_id: str = None,
        their_connection_id: str = None,
        state: str = None,
        create_did_request_dict: dict = None,
        create_did_response_dict: dict = None,
        read_did_request_dict: dict = None,
        read_did_response_dict: dict = None,
        delete_did_request_dict: dict = None,
        delete_did_response_dict: dict = None,
        error_msg: str = None,
        record_type: str = None,
        **kwargs
    ):
        super().__init__(mydata_did_registry_transaction_id, state, **kwargs)
        self.connection_id = connection_id
        self.thread_id = thread_id
        self.state = state
        self.error_msg = error_msg
        self.create_did_request_dict = create_did_request_dict
        self.create_did_response_dict = create_did_response_dict
        self.read_did_request_dict = read_did_request_dict
        self.read_did_response_dict = read_did_response_dict
        self.delete_did_request_dict = delete_did_request_dict
        self.delete_did_response_dict = delete_did_response_dict
        self.their_connection_id = their_connection_id
        self.record_type = record_type

    @property
    def mydata_did_registry_transaction_id(self) -> str:
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this transaction record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "create_did_request_dict",
                "create_did_response_dict",
                "read_did_request_dict",
                "read_did_response_dict",
                "delete_did_request_dict",
                "delete_did_response_dict",
                "state",
                "error_msg",
                "their_connection_id",
                "record_type"
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class V10MyDataDIDRegistryTransactionSchema(BaseExchangeSchema):

    class Meta:

        model_class = V10MyDataDIDRegistryTransaction

    mydata_did_registry_transaction_id = fields.Str(
        required=False,
        description="MyData registry transaction identifier",
        example=UUIDFour.EXAMPLE,
    )
    thread_id = fields.Str(
        required=False,
        description="Thread identifier",
        example=UUIDFour.EXAMPLE,
    )
    connection_id = fields.Str(
        required=False,
        description="Connection identifier",
        example=UUIDFour.EXAMPLE,
    )
    their_connection_id = fields.Str(
        required=False,
        description="Their connection identifier (Connection ID for which MyData DID will be used for ADA messages)",
        example=UUIDFour.EXAMPLE,
    )
    state = fields.Str(
        required=False,
        description="MyData transaction state",
        example=V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_SUCCESS,
    )
    create_did_request_dict = fields.Dict(
        required=False, description="Serialized create-did message dict"
    )
    create_did_response_dict = fields.Dict(
        required=False,
        description="Serialised create-did-response message dict",
    )
    read_did_request_dict = fields.Dict(
        required=False, description="Serialized read-did message dict"
    )
    read_did_response_dict = fields.Dict(
        required=False,
        description="Serialised read-did-response message dict",
    )
    delete_did_request_dict = fields.Dict(
        required=False, description="Serialized delete-did message dict"
    )
    delete_did_response_dict = fields.Dict(
        required=False,
        description="Serialised delete-did-response message dict",
    )
    error_msg = fields.Str(
        required=False, description="Error message", example="Invalid structure"
    )
    record_type = fields.Str(
        required=False,
        description="MyData transaction record type",
        example=V10MyDataDIDRegistryTransaction.RECORD_TYPE_CREATE,
    )
