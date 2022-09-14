import logging

from aiohttp import web
from aiohttp_apispec import docs, request_schema
from dexa_sdk.managers.ada_manager import V2ADAManager
from mydata_did.v1_0.routes.maps.tag_maps import TAGS_DATA_CONTROLLER_FUNCTIONS_LABEL
from mydata_did.v1_0.routes.openapi.schemas import UpdateControllerDetailsRequestSchema

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@docs(
    tags=[TAGS_DATA_CONTROLLER_FUNCTIONS_LABEL],
    summary="Send data controller details message to remote agent hosted by Data Controller",
    responses={
        200: {
            "description": "Success",
        }
    },
)
async def send_data_controller_details_message_handler(request: web.BaseRequest):
    """Send data controller details message to remote agent hosted by Data Controller."""

    context = request.app["request_context"]
    connection_id = request.match_info["connection_id"]

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    # Call the function
    await mgr.send_data_controller_details_message(connection_id)

    return web.json_response({}, status=200)


@docs(
    tags=[TAGS_DATA_CONTROLLER_FUNCTIONS_LABEL],
    summary="Update data controller details",
)
@request_schema(UpdateControllerDetailsRequestSchema())
async def update_data_controller_details(request: web.BaseRequest):
    """Update data controller details"""
    # Request context
    context = request.app["request_context"]

    # Request body
    controller_details = await request.json()

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    # Call the function
    record = await mgr.update_controller_details(
        organisation_name=controller_details.get("organisation_name"),
        cover_image_url=controller_details.get("cover_image_url"),
        logo_image_url=controller_details.get("logo_image_url"),
        location=controller_details.get("location"),
        organisation_type=controller_details.get("organisation_type"),
        description=controller_details.get("description"),
        policy_url=controller_details.get("policy_url"),
        eula_url=controller_details.get("eula_url"),
    )

    return web.json_response(record.serialize())
