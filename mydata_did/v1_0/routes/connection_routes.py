import json
import uuid
import logging
import math
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    querystring_schema,
    response_schema,
    match_info_schema,
)
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.error import StorageError
from aries_cloudagent.connections.models.connection_record import (
    ConnectionRecord,
)
from aries_cloudagent.protocols.connections.v1_0.manager import (
    ConnectionManager,
    ConnectionManagerError,
)
from ..manager import ADAManager, ADAManagerError
from ..utils.util import (
    comma_separated_str_to_list,
    get_slices,
)

from .openapi import (
    V2CreateInvitationQueryStringSchema,
    V2InvitationResultSchema,
    GenerateFirebaseDynamicLinkForConnectionInvitationMatchInfoSchema,
    GenerateFirebaseDynamicLinkForConnectionInvitationResponseSchema,
    SendExistingConnectionsMessageHandlerMatchInfoSchema,
    SendExistingConnectionsMessageHandlerRequestSchema,
    GetExistingConnectionMatchInfoSchema,
    GetExistingConnectionResponseSchema,
    ConnectionsListQueryStringSchemaV2,
    ConnectionListSchema,
)

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@docs(
    tags=["connection"],
    summary="Well-known endpoint for connection",
)
async def wellknown_connection_handler(request: web.BaseRequest):
    """Handler for well-known connection for the agent."""
    context = request.app["request_context"]
    auto_accept = True
    alias = ""
    public = False
    multi_use = False

    connection_mgr = ConnectionManager(context)
    try:
        (connection, invitation) = await connection_mgr.create_invitation(
            auto_accept=auto_accept, public=public, multi_use=multi_use, alias=alias
        )

        result = {
            "ServiceEndpoint": invitation.serialize()["serviceEndpoint"],
            "RoutingKey": "",
            "Invitation": {
                "label": invitation.label,
                "serviceEndpoint": invitation.serialize()["serviceEndpoint"],
                "routingKeys": [],
                "recipientKeys": invitation.serialize()["recipientKeys"],
                "@id": str(uuid.uuid4()),
                "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
            },
        }
    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(
    tags=["connection"],
    summary="Create a new connection invitation (Overridden API)",
)
@querystring_schema(V2CreateInvitationQueryStringSchema())
@response_schema(V2InvitationResultSchema(), 200)
async def v2_connections_create_invitation(request: web.BaseRequest):
    """
    Request handler for creating a new connection invitation.

    Args:
        request: aiohttp request object

    Returns:
        The connection invitation details

    """

    context = request.app["request_context"]
    auto_accept = json.loads(request.query.get("auto_accept", "null"))
    alias = request.query.get("alias")
    public = json.loads(request.query.get("public", "false"))
    multi_use = json.loads(request.query.get("multi_use", "false"))

    if public and not context.settings.get("public_invites"):
        raise web.HTTPForbidden(
            reason="Configuration does not include public invitations"
        )
    base_url = context.settings.get("invite_base_url")

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)
    try:
        (connection, invitation) = await mydata_did_manager.create_invitation(
            auto_accept=auto_accept, public=public, multi_use=multi_use, alias=alias
        )

        result = {
            "connection_id": connection and connection.connection_id,
            "invitation": invitation.serialize(),
            "invitation_url": invitation.to_url(base_url),
        }
    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if connection and connection.alias:
        result["alias"] = connection.alias

    return web.json_response(result)


@docs(
    tags=["connection"],
    summary="Generate firebase dynamic link for connection invitation",
)
@match_info_schema(GenerateFirebaseDynamicLinkForConnectionInvitationMatchInfoSchema())
@response_schema(
    GenerateFirebaseDynamicLinkForConnectionInvitationResponseSchema(), 200
)
async def generate_firebase_dynamic_link_for_connection_invitation_handler(
    request: web.BaseRequest,
):
    """
    Request handler for generating firebase dynamic link for connection invitation.

    Args:
        request: aiohttp request object

    Returns:
        The firebase dynamic link

    """

    context = request.app["request_context"]
    conn_id = request.match_info["conn_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)
    try:
        # Call the function
        firebase_dynamic_link = await mydata_did_manager.generate_firebase_dynamic_link_for_connection_invitation(
            conn_id
        )

    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"firebase_dynamic_link": firebase_dynamic_link})


@docs(
    tags=["connection"],
    summary="Send existing connections message to remote agent.",
    responses={
        200: {
            "description": "Success",
        }
    },
)
@match_info_schema(SendExistingConnectionsMessageHandlerMatchInfoSchema())
@request_schema(SendExistingConnectionsMessageHandlerRequestSchema())
async def send_existing_connections_message_handler(request: web.BaseRequest):
    """Send existing connections message to remote agent."""

    context = request.app["request_context"]
    conn_id = request.match_info["conn_id"]

    # Fetch request body
    body = await request.json()

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)
    try:
        # Call the function
        await mydata_did_manager.send_existing_connections_message(
            body["theirdid"], conn_id
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=200)


@docs(
    tags=["connection"],
    summary="Fetch existing connection details if any for a current connection.",
)
@match_info_schema(GetExistingConnectionMatchInfoSchema())
@response_schema(GetExistingConnectionResponseSchema(), 200)
async def get_existing_connections_handler(request: web.BaseRequest):
    """Fetch existing connection details if any for a current connection."""

    context = request.app["request_context"]
    conn_id = request.match_info["conn_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    result = {}

    # Call the function
    result = await mydata_did_manager.fetch_existing_connections_record_for_current_connection(
        conn_id
    )

    return web.json_response(result)


def connection_sort_key(conn):
    """Get the sorting key for a particular connection."""
    if conn["state"] == ConnectionRecord.STATE_INACTIVE:
        pfx = "2"
    elif conn["state"] == ConnectionRecord.STATE_INVITATION:
        pfx = "1"
    else:
        pfx = "0"
    return pfx + conn["created_at"]


@docs(
    tags=["connection"],
    summary="Query agent-to-agent connections (v2)",
)
@querystring_schema(ConnectionsListQueryStringSchemaV2())
@response_schema(ConnectionListSchema(), 200)
async def connections_list_v2(request: web.BaseRequest):
    """
    Request handler for searching connection records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context = request.app["request_context"]
    tag_filter = {}
    for param_name in (
        "invitation_id",
        "my_did",
        "their_did",
        "request_id",
    ):
        if param_name in request.query and request.query[param_name] != "":
            tag_filter[param_name] = request.query[param_name]
    post_filter = {}
    for param_name in (
        "alias",
        "initiator",
        "state",
        "their_role",
    ):
        if param_name in request.query and request.query[param_name] != "":
            post_filter[param_name] = request.query[param_name]

    # Pagination parameters
    pagination = {
        "totalCount": 0,
        "page": 0,
        "pageSize": PAGINATION_PAGE_SIZE,
        "totalPages": 0,
    }

    try:

        records = await ConnectionRecord.query(context, tag_filter, post_filter)

        # Page size from request.
        page_size = int(request.query.get("page_size", PAGINATION_PAGE_SIZE))
        pagination["pageSize"] = page_size

        # Total number of records
        pagination["totalCount"] = len(records)

        # Total number of pages.
        pagination["totalPages"] = math.ceil(
            pagination["totalCount"] / pagination["pageSize"]
        )

        # Fields to be included in the response.
        include_fields = request.query.get("include_fields")
        include_fields = (
            comma_separated_str_to_list(include_fields) if include_fields else None
        )

        results = ADAManager.serialize_connection_record(records, True, include_fields)

        # Pagination parameters
        page = request.query.get("page")
        if page:
            page = int(page)
            pagination["page"] = page

            lower, upper = get_slices(page, pagination["pageSize"])

            results = results[lower:upper]

    except (StorageError, BaseModelError, ValueError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err
    return web.json_response(
        {
            "results": results,
            "pagination": pagination if page else {},
        }
    )
