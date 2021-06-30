import json
import typing

import validators

from aiohttp import web
from aiohttp_apispec import docs, request_schema, querystring_schema, response_schema, match_info_schema, validation_middleware
from marshmallow import fields, validate, validates
from marshmallow.exceptions import ValidationError

from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import StorageNotFoundError, StorageError
from aries_cloudagent.messaging.valid import UUIDFour, UUID4
from aries_cloudagent.protocols.problem_report.v1_0 import internal_error
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.indy import IndyStorage

from .manager import ADAManager, ADAManagerError
from .models.exchange_records.registry_transaction_record import MyDataDIDRegistryTransaction, MyDataDIDRegistryTransactionSchema
from .models.exchange_records.data_agreement_didcomm_transaction_record import DataAgreementCRUDDIDCommTransaction
from .models.exchange_records.data_agreement_record import DataAgreementV1Record, DataAgreementV1RecordSchema
from .models.exchange_records.data_agreement_personal_data_record import DataAgreementPersonalDataRecordSchema, DataAgreementPersonalDataRecord
from .models.mydata_did_records import MyDataDIDRecord, MyDataDIDRecordSchema
from .models.data_agreement_model import DataAgreementPersonalData, DataAgreementPersonalDataSchema, DataAgreementV1Schema, DataAgreementV1, DATA_AGREEMENT_V1_SCHEMA_CONTEXT, DataAgreementDataPolicySchema, DataAgreementDPIASchema

from .utils.regex import MYDATA_DID


class DIDVerificationMethod(OpenAPISchema):
    registry_connection_id = fields.Str(description="ADA registry service connection ID",
                                        required=True, example=UUIDFour.EXAMPLE)
    recipient_connection_id = fields.Str(description="Recipient connection ID",
                                         required=True, example=UUIDFour.EXAMPLE)


class ReadDIDQueryStringSchema(OpenAPISchema):
    did = fields.Str(
        description="MyData decentralised identifier", required=True
    )

    connection_id = fields.UUID(
        description="Registry connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )


class CreateDataAgreementQueryStringSchema(OpenAPISchema):
    connection_id = fields.UUID(
        description="Connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )


class MyDataDIDRegistryTransactionIDMatchInfoSchema(OpenAPISchema):

    mydata_did_registry_transaction_id = fields.Str(
        description="MyData DID registry transaction identifier", required=True, **UUID4
    )


class MyDataDIDRegistryTransactionListQueryStringSchema(OpenAPISchema):

    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    thread_id = fields.UUID(
        description="Thread identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )
    state = fields.Str(
        description="MyData DID registry transaction state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(MyDataDIDRegistryTransaction, m)
                for m in vars(MyDataDIDRegistryTransaction)
                if m.startswith("STATE_")
            ]
        ),
    )
    transaction_type = fields.Str(
        description="Transaction type",
        required=False,
        validate=validate.OneOf(
            [
                getattr(MyDataDIDRegistryTransaction, m)
                for m in vars(MyDataDIDRegistryTransaction)
                if m.startswith("RECORD_TYPE_")
            ]
        ),
    )


class MyDataDIDRecordsListQueryStringSchema(OpenAPISchema):

    did = fields.Str(
        **MYDATA_DID,
        description="MyData decentralised identifier"
    )
    state = fields.Str(
        description="MyData DID registry transaction state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(MyDataDIDRecord, m)
                for m in vars(MyDataDIDRecord)
                if m.startswith("STATE_")
            ]
        ),
    )


class MyDataDIDRegistryTransactionListSchema(OpenAPISchema):

    results = fields.List(
        fields.Nested(MyDataDIDRegistryTransactionSchema()),
        description="MyData DID registry transaction records",
    )


class MyDataDIDRecordsListSchema(OpenAPISchema):

    results = fields.List(
        fields.Nested(MyDataDIDRecordSchema()),
        description="MyData DID records",
    )


class VerifiedMyDataRecordIDMatchInfoSchema(OpenAPISchema):

    did = fields.Str(
        description="MyData decentralised identifier", required=True
    )


class VerifiedMyDataRecordSchema(OpenAPISchema):
    did = fields.Str(
        **MYDATA_DID,
        description="MyData decentralised identifier"
    )
    diddoc = fields.Dict(
        description="MyData DID document"
    )


class VerifiedMyDataListSchema(OpenAPISchema):
    results = fields.List(
        fields.Nested(VerifiedMyDataRecordSchema()),
        description="Verified MyData DID records",
    )


class ReadDataAgreementMatchInfoSchema(OpenAPISchema):
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )
    connection_id = fields.UUID(
        description="Connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )


class DataAgreementQueryStringSchema(OpenAPISchema):
    """
    Query string schema for data agreements
    """

    method_of_use = fields.Str(
        description="Method of use",
        required=False,
        validate=validate.OneOf(
            [
                getattr(DataAgreementV1Record, m)
                for m in vars(DataAgreementV1Record)
                if m.startswith("METHOD_OF_USE_")
            ]
        ),
    )

    data_agreement_id = fields.Str(
        description="Data agreement identifier",
        required=False,
    )

    template_version = fields.Int(
        description="Data agreement template version",
    )

    delete_flag = fields.Bool(
        description="Delete flag to query deleted data agreements",
        required=False,
    )


class UpdateDataAgreementMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the update data agreement endpoint
    """
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )


class DeleteDataAgreementMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the delete data agreement endpoint
    """
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )


class QueryDataAgreementVersionHistoryMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the query data agreement version history endpoint
    """
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )


class DataAgreementV1RecordResponseSchema(OpenAPISchema):
    """
    Schema for data agreement v1 record response
    """
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
    data_agreement = fields.Nested(
        DataAgreementV1Schema(),
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


class CreateAndStoreDAPersonalDataInWalletRequestSchema(OpenAPISchema):

    """
    Schema for the create and store personal data in wallet request
    """

    @validates("attribute_name")
    def validate_attribute_name(self, attribute_name):
        """
        Validate attribute name
        """
        if len(attribute_name) < 3:
            raise ValidationError(
                "Attribute name must be at least 3 characters long")

    # Attribute name
    attribute_name = fields.Str(
        example="Name",
        description="Name of the attribute",
        required=True
    )

    # Attribute sensitive
    attribute_sensitive = fields.Bool(
        example=True,
        description="Sensitivity of the attribute",
        required=False
    )

    # Attribute category
    attribute_category = fields.Str(
        example="Personal",
        description="Category of the attribute",
        required=False
    )

    @validates("attribute_description")
    def validate_attribute_description(self, attribute_description):
        """
        Validate attribute description
        """
        if len(attribute_description) < 3:
            raise ValidationError(
                "Attribute description must be at least 3 characters long")
        
        if len(attribute_description) > 1000:
            raise ValidationError(
                "Attribute description must be at most 1000 characters long")

    # Attribute description
    attribute_description = fields.Str(
        example="Name of the user",
        description="Description of the attribute",
        required=False
    )


class QueryDAPersonalDataInWalletQueryStringSchema(OpenAPISchema):
    """
    Schema for the query personal data in wallet query string
    """

    attribute_sensitive = fields.Bool(
        description="Sensitivity of the attribute",
        required=False
    )

    attribute_category = fields.Str(
        description="Category of the attribute",
        required=False
    )


class ListDAPersonalDataCategoryFromWalletResponseSchema(OpenAPISchema):
    """
    Schema for the list personal data category from wallet response
    """

    # List of categories
    categories = fields.List(
        fields.Str(
            description="Category",
            example="Personal"
        ),
        description="List of categories",
        required=True
    )

class CreateOrUpdateDataAgreementPersonalDataRequestSchema(OpenAPISchema):
    """
    Schema for the create or update data agreement personal data request
    """

    attribute_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Attribute identifier",
        required=False,
    )

class CreateOrUpdateDataAgreementInWalletRequestSchema(OpenAPISchema):
    """
    Schema for the create or update data agreement in wallet request
    """

    @validates("context")
    def validate_context(self, value):
        """
        Validate data agreement schema context
        """
        if value != DATA_AGREEMENT_V1_SCHEMA_CONTEXT:
            raise ValidationError(
                f"Provided data agreement context is either not supported or invalid. "
                f"Only supported context is {DATA_AGREEMENT_V1_SCHEMA_CONTEXT}."
            )

    # Data agreement schema context i.e. which schema is used
    context = fields.Str(
        data_key="@context",
        example="https://schema.igrant.io/data-agreements/v1",
        description="Context of the schema",
        required=True
    )

    # Data agreement template identifier
    # i.e. identifier of the "prepared" data agreement template
    data_agreement_template_id = fields.Str(
        data_key="template_id",
        example=UUIDFour.EXAMPLE,
        description="Data agreement template identifier",
        dump_only=True
    )

    # Data agreement template version
    # i.e. version of the "prepared" data agreement template
    data_agreement_template_version = fields.Int(
        data_key="template_version",
        example=1,
        description="Data agreement template version",
        dump_only=True
    )

    @validates("pii_controller_name")
    def validate_pii_controller_name(self, value):
        """
        Validate data agreement schema pii controller name
        """
        if len(value) < 3:
            raise ValidationError(
                f"PII controller name must be at least 3 characters long."
            )
        if len(value) > 100:
            raise ValidationError(
                f"PII controller name must be at most 100 characters long."
            )

    # Data agreement data controller name
    # i.e. Organization name of the data controller
    pii_controller_name = fields.Str(
        data_key="data_controller_name",
        example="Happy Shopping AB",
        description="PII controller name",
        required=True
    )

    @validates("pii_controller_url")
    def validate_pii_controller_url(self, value):
        """
        Validate data agreement schema pii controller url
        """
        if not validators.url(value):
            raise ValidationError(
                f"Provided PII controller URL is not valid."
            )

    # Data agreement data controller URL
    pii_controller_url = fields.Str(
        data_key="data_controller_url",
        example="https://www.happyshopping.com",
        description="PII controller URL"
    )

    @validates("usage_purpose")
    def validate_usage_purpose(self, value):
        """
        Validate data agreement schema usage purpose
        """
        if len(value) < 3:
            raise ValidationError(
                f"Usage purpose must be at least 3 characters long."
            )
        if len(value) > 100:
            raise ValidationError(
                f"Usage purpose must be at most 100 characters long."
            )

    # Data agreement usage purpose
    usage_purpose = fields.Str(
        data_key="purpose",
        example="Customized shopping experience",
        description="Usage purpose title",
        required=True
    )

    @validates("usage_purpose_description")
    def validate_usage_purpose_description(self, value):
        """
        Validate data agreement schema usage purpose description
        """
        if len(value) < 3:
            raise ValidationError(
                f"Usage purpose description must be at least 3 characters long."
            )
        if len(value) > 500:
            raise ValidationError(
                f"Usage purpose description must be at most 500 characters long."
            )

    # Data agreement usage purpose description
    usage_purpose_description = fields.Str(
        data_key="purpose_description",
        example="Collecting user data for offering custom tailored shopping experience",
        description="Usage purpose description",
        required=True
    )

    # Data agreement legal basis
    legal_basis = fields.Str(
        data_key="lawful_basis",
        example="consent",
        description="Legal basis of processing",
        required=True,
        validate=validate.OneOf(
            [
                "consent",
                "legal_obligation",
                "contract",
                "vital_interest",
                "public_task",
                "legitimate_interest",

            ]
        )
    )

    # Data agreement method of use (i.e. how the data is used)
    # 2 method of use: "data-source" and "data-using-service"
    method_of_use = fields.Str(
        data_key="method_of_use",
        example="data-using-service",
        description="Method of use (or data exchange mode)",
        required=True,
        validate=validate.OneOf(
            [
                "data-source",
                "data-using-service",

            ]
        )
    )

    # Data agreement data policy
    data_policy = fields.Nested(DataAgreementDataPolicySchema, required=True)

    # Data agreement personal data (attributes)
    personal_data = fields.List(
        fields.Nested(CreateOrUpdateDataAgreementPersonalDataRequestSchema),
        required=True
    )

    # Data agreement DPIA metadata
    dpia = fields.Nested(DataAgreementDPIASchema, required=False)


@docs(tags=["ada_mydata-did"], summary="Fetch MyData DID registry transaction records")
@querystring_schema(MyDataDIDRegistryTransactionListQueryStringSchema)
@response_schema(MyDataDIDRegistryTransactionListSchema(), 200)
async def mydata_did_registry_transaction_records_list(request: web.BaseRequest):
    context = request.app["request_context"]
    tag_filter = {}
    if "thread_id" in request.query and request.query["thread_id"] != "":
        tag_filter["thread_id"] = request.query["thread_id"]
    if "connection_id" in request.query and request.query["connection_id"] != "":
        tag_filter["connection_id"] = request.query["connection_id"]

    post_filter = {}

    if "state" in request.query and request.query["state"] != "":
        post_filter["state"] = request.query["state"]

    if "transaction_type" in request.query and request.query["transaction_type"] != "":
        post_filter["record_type"] = request.query["transaction_type"]

    try:
        records = await MyDataDIDRegistryTransaction.query(context, tag_filter, post_filter)
        results = [record.serialize() for record in records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["ada_mydata-did"], summary="Fetch a single MyData DID registry transaction record")
@match_info_schema(MyDataDIDRegistryTransactionIDMatchInfoSchema())
@response_schema(MyDataDIDRegistryTransactionSchema(), 200)
async def mydata_did_registry_transaction_retrieve(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    mydata_did_registry_transaction_id = request.match_info["mydata_did_registry_transaction_id"]
    mydata_did_registry_transaction_record = None
    try:
        mydata_did_registry_transaction_record = await MyDataDIDRegistryTransaction.retrieve_by_id(
            context, mydata_did_registry_transaction_id
        )
        result = mydata_did_registry_transaction_record.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError) as err:
        await internal_error(err, web.HTTPBadRequest, mydata_did_registry_transaction_record, outbound_handler)

    return web.json_response(result)


@docs(tags=["ada_mydata-did"], summary="Remove an existing MyData DID registry transaction record")
@match_info_schema(MyDataDIDRegistryTransactionIDMatchInfoSchema())
async def mydata_did_registry_transaction_remove(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    mydata_did_registry_transaction_id = request.match_info["mydata_did_registry_transaction_id"]
    mydata_did_registry_transaction_record = None
    try:
        mydata_did_registry_transaction_record = await MyDataDIDRegistryTransaction.retrieve_by_id(
            context, mydata_did_registry_transaction_id
        )
        await mydata_did_registry_transaction_record.delete_record(context)
    except StorageNotFoundError as err:
        await internal_error(err, web.HTTPNotFound, mydata_did_registry_transaction_record, outbound_handler)
    except StorageError as err:
        await internal_error(err, web.HTTPBadRequest, mydata_did_registry_transaction_record, outbound_handler)

    return web.json_response({})


@docs(tags=["ada_mydata-did"], summary="Send create-did message")
@request_schema(DIDVerificationMethod())
async def send_create_did_message(request: web.BaseRequest):
    context = request.app["request_context"]

    body = await request.json()
    registry_connection_id = body.get("registry_connection_id")
    recipient_connection_id = body.get("recipient_connection_id")

    result = {}

    try:
        registry_connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, registry_connection_id)
        if not registry_connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"ADA registry connection {registry_connection_id} not ready")

        recipient_connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, recipient_connection_id)
        if not recipient_connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Recipient connection {registry_connection_id} not ready")

        mydata_did_manager = ADAManager(context=context)
        transaction_record = await mydata_did_manager.send_create_did_message(recipient_connection_record=recipient_connection_record,
                                                                              registry_connection_record=registry_connection_record)

        if transaction_record:
            result = transaction_record.serialize()
        else:
            raise web.HTTPInternalServerError(
                reason="Failed to process create-did message")
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result)


@docs(tags=["ada_mydata-did"], summary="Send read-did message")
@request_schema(ReadDIDQueryStringSchema())
async def send_read_did_message(request: web.BaseRequest):
    context = request.app["request_context"]

    body = await request.json()
    did = body.get("did")
    connection_id = body.get("connection_id")

    transaction_record = None
    result = {}

    try:
        connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"ADA registry connection {connection_id} not ready")

        mydata_did_manager = ADAManager(context=context)
        transaction_record = await mydata_did_manager.send_read_did_message(registry_connection_record=connection_record,
                                                                            did=did)

        if transaction_record:
            result = transaction_record.serialize()
        else:
            raise web.HTTPInternalServerError(
                reason="Failed to process read-did message")
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result)


@docs(tags=["ada_mydata-did"], summary="Send delete-did message")
@request_schema(ReadDIDQueryStringSchema())
async def send_delete_did_message(request: web.BaseRequest):
    context = request.app["request_context"]

    body = await request.json()
    did = body.get("did")
    connection_id = body.get("connection_id")

    transaction_record = None
    result = {}

    try:
        connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"ADA registry connection {connection_id} not ready")

        mydata_did_manager = ADAManager(context=context)
        transaction_record = await mydata_did_manager.send_delete_did_message(registry_connection_record=connection_record,
                                                                              did=did)

        if transaction_record:
            result = transaction_record.serialize()
        else:
            raise web.HTTPInternalServerError(
                reason="Failed to process delete-did message")
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result)


@docs(tags=["ada_mydata-did-registry"], summary="Fetch all verified MyData DID")
@response_schema(VerifiedMyDataListSchema(), 200)
async def fetch_all_verified_mydata_did(request: web.BaseRequest):
    context = request.app["request_context"]

    storage: IndyStorage = await context.inject(BaseStorage)
    try:
        mydata_did_info_records = await storage.search_records(
            type_filter=ADAManager.MYDATA_DID_RECORD_TYPE,
            tag_query={
                "state": ADAManager.MYDATA_DID_RECORD_VERIFIED_STATE}
        ).fetch_all()

        results = [{"did": record.tags.get("did"), "diddoc": json.loads(
            record.value)} for record in mydata_did_info_records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["ada_mydata-did-registry"], summary="Fetch verified MyData DID record")
@match_info_schema(VerifiedMyDataRecordIDMatchInfoSchema())
@response_schema(VerifiedMyDataRecordSchema(), 200)
async def fetch_verified_mydata_did_record(request: web.BaseRequest):
    context = request.app["request_context"]

    storage: IndyStorage = await context.inject(BaseStorage)

    did = request.match_info["did"]
    did_record = None

    try:
        did_record = await storage.search_records(
            type_filter=ADAManager.MYDATA_DID_RECORD_TYPE,
            tag_query={
                "state": ADAManager.MYDATA_DID_RECORD_VERIFIED_STATE, "did": did}
        ).fetch_single()

        if not did_record:
            raise web.HTTPNotFound(reason="DID record not found.")

        results = {"did": did_record.tags.get(
            "did"), "diddoc": json.loads(did_record.value)}
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(results)


@docs(tags=["ada_mydata-did"], summary="Fetch MyData DID records")
@querystring_schema(MyDataDIDRecordsListQueryStringSchema)
@response_schema(MyDataDIDRecordsListSchema(), 200)
async def mydata_did_records_records_list(request: web.BaseRequest):
    context = request.app["request_context"]
    tag_filter = {}
    if "did" in request.query and request.query["did"] != "":
        tag_filter["did"] = request.query["did"]

    post_filter = {}

    if "state" in request.query and request.query["state"] != "":
        post_filter["state"] = request.query["state"]

    try:
        records = await MyDataDIDRecord.query(context, tag_filter, post_filter)
        results = [record.serialize() for record in records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["ada_data-agreements"], summary="Read data agreement")
@match_info_schema(ReadDataAgreementMatchInfoSchema())
async def send_read_data_agreement(request: web.BaseRequest):
    """
    Send read-data-agreement message to the connection
    """

    # Request context
    context = request.app["request_context"]

    # Fetch URL path parameters
    # Data agreement ID
    data_agreement_id = request.match_info["data_agreement_id"]
    # Connection ID
    connection_id = request.match_info["connection_id"]

    # Check if data agreement ID is provided
    if not data_agreement_id:
        raise web.HTTPBadRequest(reason="Data Agreement ID missing")
    # Check if connection ID is provided
    if not connection_id:
        raise web.HTTPBadRequest(reason="Connection ID missing")

    # API Response
    result = {}

    try:
        # Fetch connection record
        connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)

        # Check if connection is ready
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"ADA registry connection {connection_id} not ready")

        # Initialise MyData DID Manager
        mydata_did_manager = ADAManager(context=context)
        # Send read-data-agreement message
        transaction_record: DataAgreementCRUDDIDCommTransaction = await mydata_did_manager.send_read_data_agreement_message(connection=connection_record, data_agreement_id=data_agreement_id)
        if transaction_record:
            result = {
                "read_data_agreement_tx_id": transaction_record.parent_message_id}

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result)


# List data agreement crud didcomm transactions from the wallet
@docs(tags=["ada_data-agreements"], summary="List data agreements crud didcomm transactions from the wallet")
async def list_data_agreements_crud_didcomm_transactions(request: web.BaseRequest):
    """
    List data agreements crud didcomm transactions from the wallet
    """
    # Request context
    context = request.app["request_context"]

    # Transactions list to be returned
    transactions = []
    try:
        # Initialise MyData DID Manager
        mydata_did_manager: ADAManager = ADAManager(
            context=context
        )

        # Fetch data agreements crud didcomm transactions from the wallet
        transactions = await mydata_did_manager.fetch_data_agreement_crud_didcomm_transactions_from_wallet()

        # Serialize transactions
        transactions = [
            {
                "da_crud_didcomm_tx_id": transaction.da_crud_didcomm_tx_id,
                "parent_message_id": transaction.parent_message_id,
                "message_family": transaction.message_family,
                "messages_list": [json.loads(message) for message in transaction.messages_list]
            }
            for transaction in transactions
        ]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": transactions})


@docs(
    tags=["ada_data-agreements"],
    summary="Create and store data agreement in wallet",
    responses={
        422: {
            "description": "Unprocessable Entity (invalid request payload)"
        }
    }
)
@request_schema(DataAgreementV1Schema())
@response_schema(DataAgreementV1RecordResponseSchema(), 201)
async def create_and_store_data_agreement_in_wallet(request: web.BaseRequest):
    """
    Create and store data agreement in wallet.

    This endpoint is used to create and store data agreement in wallet.
    Request body should contain data agreement details.
    Response body will contain data agreement details along with data agreement ID and version.
    """

    # Request context
    context = request.app["request_context"]

    # Fetch request body
    data_agreement = await request.json()

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # Generate data agreement model class instance
    data_agreement_v1 = DataAgreementV1Schema().load(data_agreement)

    # Create and store data agreement in wallet
    data_agreement_v1_record = await mydata_did_manager.create_and_store_data_agreement_in_wallet(data_agreement_v1)

    return web.json_response(data_agreement_v1_record.serialize(), status=201)


@docs(
    tags=["ada_data-agreements"],
    summary="Query data agreements in the wallet",
)
@querystring_schema(DataAgreementQueryStringSchema())
@response_schema(DataAgreementV1RecordResponseSchema(many=True), 200)
async def query_data_agreements_in_wallet(request: web.BaseRequest):
    """
    Query data agreements in the wallet.

    This endpoint is used to query data agreements in the wallet.
    Response body will contain data agreements.
    """

    # Request context
    context = request.app["request_context"]

    tag_filter = {}

    # Fetch query string parameters
    if "method_of_use" in request.query and request.query["method_of_use"] != "":
        tag_filter["method_of_use"] = request.query["method_of_use"]

    if "data_agreement_id" in request.query and request.query["data_agreement_id"] != "":
        tag_filter["data_agreement_id"] = request.query["data_agreement_id"]

    if "template_version" in request.query and request.query["template_version"] != "":
        tag_filter["template_version"] = request.query["template_version"]

    if "delete_flag" in request.query and request.query["delete_flag"] != "":
        tag_filter["delete_flag"] = "True" if request.query["delete_flag"] == "true" else "False"

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # Query data agreements in the wallet
    data_agreement_records: typing.List[DataAgreementV1Record] = await mydata_did_manager.query_data_agreements_in_wallet(tag_filter=tag_filter)

    return web.json_response([data_agreement_record.serialize() for data_agreement_record in data_agreement_records])


@docs(
    tags=["ada_data-agreements"],
    summary="Update data agreement in the wallet",
    responses={
        400: {
            "description": "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(UpdateDataAgreementMatchInfoSchema())
@request_schema(DataAgreementV1Schema())
@response_schema(DataAgreementV1RecordResponseSchema(), 200)
async def update_data_agreement_in_wallet(request: web.BaseRequest):
    """
    Update data agreement in the wallet.
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    data_agreement_id = request.match_info["data_agreement_id"]

    # Fetch request body
    data_agreement = await request.json()

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # Generate data agreement model class instance
    data_agreement_v1: DataAgreementV1 = DataAgreementV1Schema().load(data_agreement)

    try:
        # Update data agreement in the wallet
        data_agreement_v1_record: DataAgreementV1Record = await mydata_did_manager.update_data_agreement_in_wallet(data_agreement_id=data_agreement_id, data_agreement=data_agreement_v1)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(data_agreement_v1_record.serialize())


@docs(
    tags=["ada_data-agreements"],
    summary="Delete data agreement in the wallet",
    responses={
        204: {
            "description": "No Content (data agreement deleted)"
        },
        400: {
            "description": "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(DeleteDataAgreementMatchInfoSchema())
async def delete_data_agreement_in_wallet(request: web.BaseRequest):
    """
    Delete data agreement in the wallet.
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    data_agreement_id = request.match_info["data_agreement_id"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Delete data agreement in the wallet
        await mydata_did_manager.delete_data_agreement_in_wallet(data_agreement_id=data_agreement_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=["ada_data-agreements"],
    summary="Query version history of a data agreement",
    responses={
        400: {
            "description": "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(QueryDataAgreementVersionHistoryMatchInfoSchema())
@response_schema(DataAgreementV1RecordResponseSchema(many=True), 200)
async def query_data_agreement_version_history(request: web.BaseRequest):
    """
    Query version history of a data agreement.
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    data_agreement_id = request.match_info["data_agreement_id"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:

        # Query version history of a data agreement
        data_agreement_version_history_records: typing.List[DataAgreementV1Record] = await mydata_did_manager.query_data_agreement_version_history(data_agreement_id=data_agreement_id)
    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response([data_agreement_version_history_record.serialize() for data_agreement_version_history_record in data_agreement_version_history_records])


@docs(
    tags=["ada_data-agreements"],
    summary="Create and store data agreement personal data in wallet",
    responses={
        422: {
            "description": "Unprocessable Entity (invalid request payload)"
        }
    }
)
@request_schema(CreateAndStoreDAPersonalDataInWalletRequestSchema())
@response_schema(DataAgreementPersonalDataRecordSchema(), 201)
async def create_and_store_da_personal_data_in_wallet(request: web.BaseRequest):
    """
    Create and store data agreement personal data in wallet.
    """

    # Request context
    context = request.app["request_context"]

    # Fetch request body
    data_agreement_personal_data = await request.json()

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # Generate data agreement personal data model class instance
    data_agreement_personal_data: DataAgreementPersonalData = DataAgreementPersonalDataSchema(
    ).load(data_agreement_personal_data)

    try:
        # Create and store data agreement personal data in wallet
        data_agreement_personal_data_record: DataAgreementPersonalDataRecord = await mydata_did_manager.create_and_store_da_personal_data_in_wallet(personal_data=data_agreement_personal_data)

    except ADAManagerError as err:
        raise web.HTTPUnprocessableEntity(reason=err.roll_up) from err

    return web.json_response(data_agreement_personal_data_record.serialize(), status=201)


@docs(
    tags=["ada_data-agreements"],
    summary="Query data agreement personal data in wallet",
)
@querystring_schema(QueryDAPersonalDataInWalletQueryStringSchema())
@response_schema(DataAgreementPersonalDataRecordSchema(many=True), 200)
async def query_da_personal_data_in_wallet(request: web.BaseRequest):
    """
    Query data agreement personal data in wallet.
    """

    # Request context
    context = request.app["request_context"]

    # Fetch query string parameters
    tag_filter = {}
    if "attribute_category" in request.query and request.query["attribute_category"] != "":
        tag_filter["attribute_category"] = request.query["attribute_category"]

    if "attribute_sensitive" in request.query and request.query["attribute_sensitive"] != "":
        tag_filter["attribute_sensitive"] = "True" if request.query["attribute_sensitive"] == "true" else "False"

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Query data agreement personal data in wallet
        data_agreement_personal_data_records: typing.List[DataAgreementPersonalDataRecord] = await mydata_did_manager.query_da_personal_data_in_wallet(tag_filter=tag_filter)
    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response([data_agreement_personal_data_record.serialize() for data_agreement_personal_data_record in data_agreement_personal_data_records])


@docs(
    tags=["ada_data-agreements"],
    summary="List data agreement personal data category from wallet"
)
@response_schema(ListDAPersonalDataCategoryFromWalletResponseSchema(), 200)
async def list_da_personal_data_category_from_wallet(request: web.BaseRequest):
    """
    List data agreement personal data category from wallet.
    """

    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    response = {"categories": []}

    try:
        # List data agreement personal data category from wallet
        data_agreement_personal_data_category_list: typing.List[str] = await mydata_did_manager.list_da_personal_data_category_from_wallet()

        response["categories"] = data_agreement_personal_data_category_list

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(response)

async def register(app: web.Application):
    app.add_routes(
        [
            web.get(
                "/mydata-did/transaction-records",
                mydata_did_registry_transaction_records_list,
                allow_head=False
            ),
            web.get(
                "/mydata-did/transaction-records/{mydata_did_registry_transaction_id}",
                mydata_did_registry_transaction_retrieve,
                allow_head=False,
            ),
            web.post(
                "/mydata-did/didcomm/create-did",
                send_create_did_message
            ),
            web.post(
                "/mydata-did/didcomm/read-did",
                send_read_did_message
            ),
            web.post(
                "/mydata-did/didcomm/delete-did",
                send_delete_did_message
            ),
            web.delete(
                "/mydata-did/transaction-records/{mydata_did_registry_transaction_id}",
                mydata_did_registry_transaction_remove,
            ),
            web.get(
                "/mydata-did-registry/admin/verified-did",
                fetch_all_verified_mydata_did,
                allow_head=False
            ),
            web.get(
                "/mydata-did-registry/admin/verified-did/{did}",
                fetch_verified_mydata_did_record,
                allow_head=False
            ),
            web.get(
                "/mydata-did/did-records",
                mydata_did_records_records_list,
                allow_head=False
            ),
            web.post(
                "/data-agreements/didcomm/{connection_id}/read-data-agreement/{data_agreement_id}",
                send_read_data_agreement
            ),
            web.get(
                "/data-agreements/didcomm/transactions",
                list_data_agreements_crud_didcomm_transactions,
                allow_head=False
            ),
            web.post(
                "/data-agreements",
                create_and_store_data_agreement_in_wallet,
            ),
            web.get(
                "/data-agreements",
                query_data_agreements_in_wallet,
                allow_head=False
            ),
            web.put(
                "/data-agreements/{data_agreement_id}",
                update_data_agreement_in_wallet,
            ),
            web.delete(
                "/data-agreements/{data_agreement_id}",
                delete_data_agreement_in_wallet,
            ),
            web.get(
                "/data-agreements/version-history/{data_agreement_id}",
                query_data_agreement_version_history,
                allow_head=False
            ),
            web.post(
                "/data-agreements/personal-data",
                create_and_store_da_personal_data_in_wallet,
            ),
            web.get(
                "/data-agreements/personal-data",
                query_da_personal_data_in_wallet,
                allow_head=False
            ),
            web.get(
                "/data-agreements/personal-data/category",
                list_da_personal_data_category_from_wallet,
                allow_head=False
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "ada_mydata-did",
            "description": "A new DID method that allows different objects in iGrant.io automated data agreements (ADA) specifications to be treated as a valid identifier",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/did-spec.md"},
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "ada_mydata-did-registry",
            "description": "MyData registry admin only functions",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/did-spec.md"},
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "ada_data-agreements",
            "description": "Data agreement functions",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/didcomm-protocol-spec.md"},
        }
    )
