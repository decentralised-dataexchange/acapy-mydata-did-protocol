import os
import typing
import logging
import jwt

from aiohttp import web
from aiohttp import frozenlist
from ..manager import ADAManager, ADAManagerError

from .maps.tag_maps import (
    TAGS_MYDATA_DID_OPERATIONS,
    TAGS_DATA_AGREEMENT_CORE_FUNCTIONS,
    TAGS_DATA_AGREEMENT_AUDITOR_FUNCTIONS,
    TAGS_JSONLD_FUNCTIONS,
    TAGS_DATA_CONTROLLER_FUNCTIONS
)

from .maps.route_maps import ROUTES_ADA


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

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    try:
        # Fetch iGrant.io config from os environment.
        config: dict = await mydata_did_manager.fetch_igrantio_config_from_os_environ()
    except ADAManagerError:
        # iGrant.io config is not available.
        # Proceed without authentication.

        return await handler(request)

    # API Key secret
    api_key_secret = config.get("igrantio_org_api_key_secret")

    # Fetch authorization header.
    authorization_header = request.headers.get("Authorization")

    # Fetch api key from authorization header.
    api_key = authorization_header.split("ApiKey ")[1] if authorization_header else None

    if not api_key:
        raise web.HTTPUnauthorized(reason="Missing Authorization header.")

    # Authenticate the request.
    try:
        jwt.decode(api_key, api_key_secret, algorithms=["HS256"])
    except jwt.exceptions.InvalidTokenError:
        try:
            jwt.decode(
                api_key, api_key_secret, algorithms=["HS256"], audience="dataverifier"
            )
        except jwt.exceptions.InvalidTokenError:
            raise web.HTTPUnauthorized(reason="Invalid API Key.")

    # Override the api key in environment variable.
    os.environ["IGRANTIO_ORG_API_KEY"] = api_key

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
