import logging
from aiohttp import web
from aiohttp_apispec import (
    docs,
)
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.protocols.connections.v1_0.manager import (
    ConnectionManagerError,
)
from ..manager import ADAManager, ADAManagerError
from ..routes.maps.tag_maps import (
    TAGS_DATA_CONTROLLER_FUNCTIONS_LABEL,
)

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
    mydata_did_manager: ADAManager = ADAManager(context=context)
    try:
        # Call the function
        await mydata_did_manager.send_data_controller_details_message(connection_id)

    except (ConnectionManagerError, BaseModelError, ADAManagerError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    except Exception as err:
        raise web.HTTPInternalServerError(reason=str(err)) from err

    return web.json_response({}, status=200)
