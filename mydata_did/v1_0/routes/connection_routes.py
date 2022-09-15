import json
import logging
import uuid

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from aries_cloudagent.connections.models.connection_record import (
    ConnectionRecord,
    ConnectionRecordSchema,
)
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.protocols.connections.v1_0.manager import (
    ConnectionManager,
    ConnectionManagerError,
)
from aries_cloudagent.protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitation,
)
from aries_cloudagent.protocols.connections.v1_0.routes import (
    ReceiveInvitationQueryStringSchema,
)
from aries_cloudagent.storage.error import StorageError
from dexa_sdk.managers.ada_manager import V2ADAManager
from dexa_sdk.utils import clean_and_get_field_from_dict
from mydata_did.v1_0.manager import ADAManagerError
from mydata_did.v1_0.routes.openapi.schemas import (
    ConnectionListSchema,
    ConnectionsListQueryStringSchemaV2,
    GenerateFirebaseDynamicLinkForConnectionInvitationMatchInfoSchema,
    GenerateFirebaseDynamicLinkForConnectionInvitationResponseSchema,
    GetExistingConnectionMatchInfoSchema,
    GetExistingConnectionResponseSchema,
    SendExistingConnectionsMessageHandlerMatchInfoSchema,
    SendExistingConnectionsMessageHandlerRequestSchema,
    V2CreateInvitationQueryStringSchema,
    V2InvitationResultSchema,
    V2ReceiveConnectionInvitationRequestSchema,
)
from mydata_did.v1_0.utils.util import str_to_bool

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
    mgr = V2ADAManager(context=context)
    try:
        (connection, invitation) = await mgr.create_invitation(
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

    # Request context.
    context = request.app["request_context"]

    # Path params.
    conn_id = request.match_info["conn_id"]

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)
    try:
        # Call the function
        res = await mgr.create_connection_qr_code(conn_id)

    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(res)


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
    theirdid = body.get("theirdid")

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    try:
        # Call the function
        await mgr.send_existing_connections_message(theirdid, conn_id)

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

    # Request context
    context = request.app["request_context"]

    # Path params.
    conn_id = request.match_info["conn_id"]

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    # Call the function
    result = await mgr.get_existing_connection_record_for_new_connection_id(conn_id)
    result = result.serialize() if result else {}

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
        "invitation_key",
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
    page = clean_and_get_field_from_dict(request.query, "page")
    page = int(page) if page is not None else page
    page_size = clean_and_get_field_from_dict(request.query, "page_size")
    page_size = int(page_size) if page_size is not None else page_size

    # Category
    org_flag = clean_and_get_field_from_dict(request.query, "org_flag")
    marketplace_flag = clean_and_get_field_from_dict(request.query, "marketplace_flag")

    mgr = V2ADAManager(context)

    pagination_result = await mgr.query_connections_and_categorise_results(
        tag_filter,
        post_filter,
        page if page else 1,
        page_size if page_size else 10,
        str_to_bool(org_flag) if org_flag else org_flag,
        str_to_bool(marketplace_flag) if marketplace_flag else marketplace_flag,
    )

    return web.json_response(pagination_result._asdict())


@docs(
    tags=["connection"],
    summary="Receive a new connection invitation",
)
@querystring_schema(ReceiveInvitationQueryStringSchema())
@request_schema(V2ReceiveConnectionInvitationRequestSchema())
@response_schema(ConnectionRecordSchema(), 200)
async def v2_connections_receive_invitation(request: web.BaseRequest):
    """
    Request handler for receiving a new connection invitation.

    Args:
        request: aiohttp request object

    Returns:
        The resulting connection record details

    """
    context = request.app["request_context"]
    if context.settings.get("admin.no_receive_invites"):
        raise web.HTTPForbidden(
            reason="Configuration does not allow receipt of invitations"
        )
    connection_mgr = ConnectionManager(context)

    body = await request.json()
    connection_url = body.get("connection_url")

    try:
        invitation = ConnectionInvitation.from_url(connection_url)
        auto_accept = json.loads(request.query.get("auto_accept", "null"))
        alias = request.query.get("alias")
        connection = await connection_mgr.receive_invitation(
            invitation, auto_accept=auto_accept, alias=alias
        )
        result = connection.serialize()
    except (ConnectionManagerError, StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)
