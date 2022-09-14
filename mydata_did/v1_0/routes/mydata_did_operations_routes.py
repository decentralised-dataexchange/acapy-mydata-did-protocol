import json
import logging

from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, querystring_schema, response_schema
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.error import StorageError
from aries_cloudagent.storage.indy import IndyStorage
from aries_cloudagent.storage.record import StorageRecord
from mydata_did.v1_0.manager import ADAManager, ADAManagerError
from mydata_did.v1_0.routes.maps.tag_maps import TAGS_MYDATA_DID_OPERATIONS_LABEL
from mydata_did.v1_0.routes.openapi.schemas import (
    MyDataDIDRemoteRecordResponseSchema,
    MyDataDIDRemoteRecordsQueryStringSchema,
    SendReadDIDMessageMatchInfoSchema,
)

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@docs(
    tags=[TAGS_MYDATA_DID_OPERATIONS_LABEL],
    summary="Send read-did didcomm message to MyData DID registry",
)
@match_info_schema(SendReadDIDMessageMatchInfoSchema())
async def send_read_did_message_to_mydata_did_registry(request: web.BaseRequest):
    """
    Request handler for sending read-did didcomm message to MyData DID registry
    """

    # Context
    context = request.app["request_context"]

    # did:mydata identifier
    did = request.match_info["did"]

    result = {}

    try:

        # Initialize MyData DID manager
        mydata_did_manager = ADAManager(context=context)

        # Send read-did message to MyData DID registry
        transaction_record = await mydata_did_manager.send_read_did_message(did=did)

        if transaction_record:
            temp_record = transaction_record.serialize()
            temp_messages_list = []
            for message in temp_record.get("messages_list", []):
                temp_messages_list.append(json.loads(message))

                temp_record["messages_list"] = temp_messages_list

            result = temp_record

        else:
            raise web.HTTPInternalServerError(reason="Failed to send read-did message")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(
    tags=[TAGS_MYDATA_DID_OPERATIONS_LABEL],
    summary="Fetch MyData DID remote records.",
)
@querystring_schema(MyDataDIDRemoteRecordsQueryStringSchema())
@response_schema(MyDataDIDRemoteRecordResponseSchema(many=True), 200)
async def mydata_did_remote_records_list(request: web.BaseRequest):
    """
    Request handler for fetching MyData DID remote records
    """

    # Context
    context = request.app["request_context"]

    # Query string parameters
    tag_filter = {}
    if "did" in request.query and request.query["did"] != "":
        tag_filter["did"] = request.query["did"]

    if "sov_verkey" in request.query and request.query["sov_verkey"] != "":
        tag_filter["sov_verkey"] = request.query["sov_verkey"]

    if "status" in request.query and request.query["status"] != "":
        tag_filter["status"] = request.query["status"]

    results = []

    try:
        # Storage
        storage: IndyStorage = await context.inject(BaseStorage)

        # Search remote records
        remote_records: StorageRecord = await storage.search_records(
            type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REMOTE, tag_query=tag_filter
        ).fetch_all()

        for remote_record in remote_records:
            results.append(
                {
                    "did": remote_record.tags.get("did"),
                    "sov_verkey": remote_record.tags.get("sov_verkey"),
                    "status": remote_record.tags.get("status"),
                    "diddoc": json.loads(remote_record.value),
                }
            )

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(results)
