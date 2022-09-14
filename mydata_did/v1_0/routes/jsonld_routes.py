import logging

from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, request_schema
from dexa_sdk.managers.ada_manager import V2ADAManager
from mydata_did.v1_0.routes.maps.tag_maps import TAGS_JSONLD_FUNCTIONS_LABEL
from mydata_did.v1_0.routes.openapi.schemas import (
    SendJSONLDDIDCommProcessedDataMessageHandlerMatchInfoSchema,
    SendJSONLDDIDCommProcessedDataMessageHandlerRequestSchema,
)

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@docs(
    tags=[TAGS_JSONLD_FUNCTIONS_LABEL],
    summary="Send JSON-LD processed-data didcomm message to the remote agent.",
    responses={
        204: {
            "description": "Success",
        },
    },
)
@match_info_schema(SendJSONLDDIDCommProcessedDataMessageHandlerMatchInfoSchema())
@request_schema(SendJSONLDDIDCommProcessedDataMessageHandlerRequestSchema())
async def send_json_ld_didcomm_processed_data_message_handler(request: web.BaseRequest):
    """Send JSON-LD didcomm processed data message handler."""

    # Context.
    context = request.app["request_context"]

    # Fetch path parameters.
    connection_id = request.match_info["connection_id"]

    # Fetch request body
    body = await request.json()
    data = body.get("data")
    signature_options = body.get("signature_options")

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    await mgr.send_json_ld_processed_message(
        connection_id=connection_id,
        data=data,
        signature_options=signature_options,
    )

    return web.json_response({}, status=204)
