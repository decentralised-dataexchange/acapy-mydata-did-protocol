import logging
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    match_info_schema,
)

from ..manager import ADAManager, ADAManagerError
from ..routes.maps.tag_maps import (
    TAGS_JSONLD_FUNCTIONS_LABEL,
)

from .openapi import (
    SendJSONLDDIDCommProcessedDataMessageHandlerRequestSchema,
    SendJSONLDDIDCommProcessedDataMessageHandlerMatchInfoSchema,
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

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    try:

        # Call the function.

        await mydata_did_manager.send_json_ld_processed_message(
            connection_id=connection_id,
            data=body.get("data", {}),
            signature_options=body.get("signature_options", {}),
            proof_chain=body.get("proof_chain", False),
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)
