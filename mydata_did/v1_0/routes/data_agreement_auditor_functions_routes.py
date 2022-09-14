import logging

from aiohttp import web
from aiohttp_apispec import docs, querystring_schema, response_schema
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.error import StorageError
from dexa_sdk.managers.ada_manager import V2ADAManager
from dexa_sdk.utils import clean_and_get_field_from_dict
from mydata_did.v1_0.models.data_agreement_instance_model import (
    DataAgreementInstanceSchema,
)
from mydata_did.v1_0.routes.maps.tag_maps import (
    TAGS_DATA_AGREEMENT_AUDITOR_FUNCTIONS_LABEL,
)
from mydata_did.v1_0.routes.openapi.schemas import (
    QueryDataAgreementInstanceQueryStringSchema,
)

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@docs(
    tags=[TAGS_DATA_AGREEMENT_AUDITOR_FUNCTIONS_LABEL],
    summary="Query data agreement instances",
)
@querystring_schema(QueryDataAgreementInstanceQueryStringSchema())
@response_schema(DataAgreementInstanceSchema(many=True), 200)
async def query_data_agreement_instances(request: web.BaseRequest):
    """
    Request handler for querying data agreement instances.
    """

    # Context
    context = request.app["request_context"]

    instance_id = clean_and_get_field_from_dict(request.query, "instance_id")
    template_id = clean_and_get_field_from_dict(request.query, "template_id")
    template_version = clean_and_get_field_from_dict(request.query, "template_version")
    method_of_use = clean_and_get_field_from_dict(request.query, "method_of_use")
    third_party_data_sharing = clean_and_get_field_from_dict(
        request.query, "third_party_data_sharing"
    )
    data_ex_id = clean_and_get_field_from_dict(request.query, "data_ex_id")
    data_subject_did = clean_and_get_field_from_dict(request.query, "data_subject_did")
    page = clean_and_get_field_from_dict(request.query, "page")
    page = int(page) if page is not None else page
    page_size = clean_and_get_field_from_dict(request.query, "page_size")
    page_size = int(page_size) if page_size is not None else page_size

    try:

        # Initialise MyData DID Manager
        manager: V2ADAManager = V2ADAManager(context=context)

        # Get the data agreement instances
        paginationResult = await manager.query_data_agreement_instances(
            instance_id,
            template_id,
            template_version,
            method_of_use,
            third_party_data_sharing,
            data_ex_id,
            data_subject_did,
            page if page else 1,
            page_size if page_size else 10,
        )

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(paginationResult._asdict())
