import json

from aiohttp import web
from aiohttp_apispec import docs, request_schema, querystring_schema, response_schema, match_info_schema
from marshmallow import fields, validate

from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.storage.error import StorageNotFoundError, StorageError
from aries_cloudagent.messaging.valid import UUIDFour, UUID4
from aries_cloudagent.protocols.problem_report.v1_0 import internal_error
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.indy import IndyStorage

from .manager import MyDataDIDManager
from .models.registry_transaction_records import V10MyDataDIDRegistryTransaction, V10MyDataDIDRegistryTransactionSchema
from .models.mydata_did_records import V10MyDataDIDRecord, V10MyDataDIDRecordSchema
from .utils.regex import MYDATA_DID


class DIDVerificationMethod(OpenAPISchema):
    registry_connection_id = fields.Str(description="ADA registry service connection ID",
                                        required=True, example=UUIDFour.EXAMPLE)
    recipient_connection_id = fields.Str(description="Recipient connection ID",
                                         required=True, example=UUIDFour.EXAMPLE)


class V10ReadDIDQueryStringSchema(OpenAPISchema):
    did = fields.Str(
        description="MyData decentralised identifier", required=True
    )

    connection_id = fields.UUID(
        description="Registry connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )


class MyDataDIDRegistryTransactionIDMatchInfoSchema(OpenAPISchema):

    mydata_did_registry_transaction_id = fields.Str(
        description="MyData DID registry transaction identifier", required=True, **UUID4
    )


class V10MyDataDIDRegistryTransactionListQueryStringSchema(OpenAPISchema):

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
                getattr(V10MyDataDIDRegistryTransaction, m)
                for m in vars(V10MyDataDIDRegistryTransaction)
                if m.startswith("STATE_")
            ]
        ),
    )
    transaction_type = fields.Str(
        description="Transaction type",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V10MyDataDIDRegistryTransaction, m)
                for m in vars(V10MyDataDIDRegistryTransaction)
                if m.startswith("RECORD_TYPE_")
            ]
        ),
    )


class V10MyDataDIDRecordsListQueryStringSchema(OpenAPISchema):

    did = fields.Str(
        **MYDATA_DID,
        description="MyData decentralised identifier"
    )
    state = fields.Str(
        description="MyData DID registry transaction state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V10MyDataDIDRecord, m)
                for m in vars(V10MyDataDIDRecord)
                if m.startswith("STATE_")
            ]
        ),
    )

class V10MyDataDIDRegistryTransactionListSchema(OpenAPISchema):

    results = fields.List(
        fields.Nested(V10MyDataDIDRegistryTransactionSchema()),
        description="MyData DID registry transaction records",
    )


class V10MyDataDIDRecordsListSchema(OpenAPISchema):

    results = fields.List(
        fields.Nested(V10MyDataDIDRecordSchema()),
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


@docs(tags=["mydata-did"], summary="Fetch MyData DID registry transaction records")
@querystring_schema(V10MyDataDIDRegistryTransactionListQueryStringSchema)
@response_schema(V10MyDataDIDRegistryTransactionListSchema(), 200)
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
        records = await V10MyDataDIDRegistryTransaction.query(context, tag_filter, post_filter)
        results = [record.serialize() for record in records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["mydata-did"], summary="Fetch a single MyData DID registry transaction record")
@match_info_schema(MyDataDIDRegistryTransactionIDMatchInfoSchema())
@response_schema(V10MyDataDIDRegistryTransactionSchema(), 200)
async def mydata_did_registry_transaction_retrieve(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    mydata_did_registry_transaction_id = request.match_info["mydata_did_registry_transaction_id"]
    mydata_did_registry_transaction_record = None
    try:
        mydata_did_registry_transaction_record = await V10MyDataDIDRegistryTransaction.retrieve_by_id(
            context, mydata_did_registry_transaction_id
        )
        result = mydata_did_registry_transaction_record.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError) as err:
        await internal_error(err, web.HTTPBadRequest, mydata_did_registry_transaction_record, outbound_handler)

    return web.json_response(result)


@docs(tags=["mydata-did"], summary="Remove an existing MyData DID registry transaction record")
@match_info_schema(MyDataDIDRegistryTransactionIDMatchInfoSchema())
async def mydata_did_registry_transaction_remove(request: web.BaseRequest):
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    mydata_did_registry_transaction_id = request.match_info["mydata_did_registry_transaction_id"]
    mydata_did_registry_transaction_record = None
    try:
        mydata_did_registry_transaction_record = await V10MyDataDIDRegistryTransaction.retrieve_by_id(
            context, mydata_did_registry_transaction_id
        )
        await mydata_did_registry_transaction_record.delete_record(context)
    except StorageNotFoundError as err:
        await internal_error(err, web.HTTPNotFound, mydata_did_registry_transaction_record, outbound_handler)
    except StorageError as err:
        await internal_error(err, web.HTTPBadRequest, mydata_did_registry_transaction_record, outbound_handler)

    return web.json_response({})


@docs(tags=["mydata-did"], summary="Send create-did message")
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

        mydata_did_manager = MyDataDIDManager(context=context)
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


@docs(tags=["mydata-did"], summary="Send read-did message")
@request_schema(V10ReadDIDQueryStringSchema())
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

        mydata_did_manager = MyDataDIDManager(context=context)
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


@docs(tags=["mydata-did"], summary="Send delete-did message")
@request_schema(V10ReadDIDQueryStringSchema())
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

        mydata_did_manager = MyDataDIDManager(context=context)
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


@docs(tags=["mydata-did-admin"], summary="Fetch all verified MyData DID")
@response_schema(VerifiedMyDataListSchema(), 200)
async def fetch_all_verified_mydata_did(request: web.BaseRequest):
    context = request.app["request_context"]

    storage: IndyStorage = await context.inject(BaseStorage)
    try:
        mydata_did_info_records = await storage.search_records(
            type_filter=MyDataDIDManager.MYDATA_DID_RECORD_TYPE,
            tag_query={
                "state": MyDataDIDManager.MYDATA_DID_RECORD_VERIFIED_STATE}
        ).fetch_all()

        results = [{"did": record.tags.get("did"), "diddoc": json.loads(
            record.value)} for record in mydata_did_info_records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["mydata-did-admin"], summary="Fetch verified MyData DID record")
@match_info_schema(VerifiedMyDataRecordIDMatchInfoSchema())
@response_schema(VerifiedMyDataRecordSchema(), 200)
async def fetch_verified_mydata_did_record(request: web.BaseRequest):
    context = request.app["request_context"]

    storage: IndyStorage = await context.inject(BaseStorage)

    did = request.match_info["did"]
    did_record = None

    try:
        did_record = await storage.search_records(
            type_filter=MyDataDIDManager.MYDATA_DID_RECORD_TYPE,
            tag_query={
                "state": MyDataDIDManager.MYDATA_DID_RECORD_VERIFIED_STATE, "did": did}
        ).fetch_single()

        if not did_record:
            raise web.HTTPNotFound(reason="DID record not found.")

        results = {"did": did_record.tags.get(
            "did"), "diddoc": json.loads(did_record.value)}
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(results)


@docs(tags=["mydata-did"], summary="Fetch MyData DID records")
@querystring_schema(V10MyDataDIDRecordsListQueryStringSchema)
@response_schema(V10MyDataDIDRecordsListSchema(), 200)
async def mydata_did_records_records_list(request: web.BaseRequest):
    context = request.app["request_context"]
    tag_filter = {}
    if "did" in request.query and request.query["did"] != "":
        tag_filter["did"] = request.query["did"]

    post_filter = {}

    if "state" in request.query and request.query["state"] != "":
        post_filter["state"] = request.query["state"]

    try:
        records = await V10MyDataDIDRecord.query(context, tag_filter, post_filter)
        results = [record.serialize() for record in records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


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
                "/mydata-did/create-did",
                send_create_did_message
            ),
            web.post(
                "/mydata-did/read-did",
                send_read_did_message
            ),
            web.post(
                "/mydata-did/delete-did",
                send_delete_did_message
            ),
            web.delete(
                "/mydata-did/transaction-records/{mydata_did_registry_transaction_id}",
                mydata_did_registry_transaction_remove,
            ),
            web.get(
                "/mydata-did/verified",
                fetch_all_verified_mydata_did,
                allow_head=False
            ),
            web.get(
                "/mydata-did/verified/{did}",
                fetch_verified_mydata_did_record,
                allow_head=False
            ),
            web.get(
                "/mydata-did/did-records",
                mydata_did_records_records_list,
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
            "name": "mydata-did",
            "description": "A new DID method that allows different objects in iGrant.io automated data agreements (ADA) specifications to be treated as a valid identifier",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/did-spec.md"},
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "mydata-did-admin",
            "description": "MyData registry admin only functions",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/did-spec.md"},
        }
    )
