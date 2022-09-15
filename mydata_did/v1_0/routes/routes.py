import logging
import typing

import jwt
from aiohttp import frozenlist, web
from mydata_did.v1_0.routes.maps.route_maps import ROUTES_ADA
from mydata_did.v1_0.routes.maps.tag_maps import (
    TAGS_DATA_AGREEMENT_AUDITOR_FUNCTIONS,
    TAGS_DATA_AGREEMENT_CORE_FUNCTIONS,
    TAGS_DATA_CONTROLLER_FUNCTIONS,
    TAGS_DATA_SUBJECT_FUNCTIONS,
    TAGS_JSONLD_FUNCTIONS,
    TAGS_MYDATA_DID_OPERATIONS,
)

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@web.middleware
async def authentication_middleware(
    request: web.BaseRequest, handler: typing.Coroutine
):
    """
    Authentication middleware.

    Authenticate the request if the request headers contains
    Authorization header with value of ApiKey <api_key>.
    """

    # Context.
    context = request.app["request_context"]

    # Fetch iGrant.io config from os environment.
    config_api_key_secret = context.settings.get(
        "intermediary.igrantio_org_api_key_secret"
    )
    config_igrantio_authentication = context.settings.get(
        "intermediary.igrantio_authentication"
    )

    if not config_igrantio_authentication or "webhook" in request.path:
        # Intermediary config not available.
        return await handler(request)

    # Fetch authorization header.
    authorization_header = request.headers.get("Authorization")

    # Fetch api key from authorization header.
    header_api_key = (
        authorization_header.split("ApiKey ")[1] if authorization_header else None
    )

    if not header_api_key:
        raise web.HTTPUnauthorized(reason="Missing Authorization header.")

    # Authenticate the request.
    try:
        jwt.decode(header_api_key, config_api_key_secret, algorithms=["HS256"])
    except jwt.exceptions.InvalidTokenError:
        try:
            jwt.decode(
                header_api_key,
                config_api_key_secret,
                algorithms=["HS256"],
                audience="dataverifier",
            )
        except jwt.exceptions.InvalidTokenError:
            raise web.HTTPUnauthorized(reason="Invalid API Key.")

    # Override settings api key.
    context.settings["intermediary.igrantio_org_api_key"] = header_api_key

    # Call the handler.
    return await handler(request)


async def register(app: web.Application):

    app._middlewares = frozenlist.FrozenList(
        app.middlewares[:] + [authentication_middleware]
    )

    app.add_routes(ROUTES_ADA)


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []

    app._state["swagger_dict"]["tags"].append(TAGS_MYDATA_DID_OPERATIONS)
    app._state["swagger_dict"]["tags"].append(TAGS_DATA_AGREEMENT_CORE_FUNCTIONS)
    app._state["swagger_dict"]["tags"].append(TAGS_DATA_AGREEMENT_AUDITOR_FUNCTIONS)
    app._state["swagger_dict"]["tags"].append(TAGS_JSONLD_FUNCTIONS)
    app._state["swagger_dict"]["tags"].append(TAGS_DATA_CONTROLLER_FUNCTIONS)
    app._state["swagger_dict"]["tags"].append(TAGS_DATA_SUBJECT_FUNCTIONS)
