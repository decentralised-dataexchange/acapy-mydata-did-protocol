import logging

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.error import StorageError
from dexa_sdk.managers.ada_manager import V2ADAManager
from dexa_sdk.managers.dexa_manager import DexaManager
from dexa_sdk.utils import clean_and_get_field_from_dict
from mydata_did.v1_0.manager import ADAManagerError
from mydata_did.v1_0.models.exchange_records.data_agreement_personal_data_record import (
    DataAgreementPersonalDataRecordSchema,
)
from mydata_did.v1_0.routes.maps.tag_maps import (
    TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL,
    TAGS_DATA_SUBJECT_FUNCTIONS_LABEL,
)
from mydata_did.v1_0.routes.openapi.schemas import (
    ConfigureCustomerIdentificationDAMatchInfoSchema,
    CreateOrUpdateDataAgreementInWalletQueryStringSchema,
    CreateOrUpdateDataAgreementInWalletRequestSchema,
    DataAgreementQRCodeMatchInfoSchema,
    DataAgreementQueryStringSchema,
    DataAgreementV1RecordResponseSchema,
    DeleteDaPersonalDataInWalletMatchInfoSchema,
    DeleteDataAgreementMatchInfoSchema,
    GenerateDataAgreementQrCodePayloadQueryStringSchema,
    GenerateDataAgreementQrCodePayloadResponseSchema,
    PublishDataAgreementMatchInfoSchema,
    QueryDaPersonalDataInWalletQueryStringSchema,
    QueryDataAgreementQrCodeMetadataRecordsMatchInfoSchema,
    QueryDataAgreementQRCodeMetadataRecordsResponseSchema,
    RemoveDataAgreementQrCodeMetadataRecordMatchInfoSchema,
    SendDataAgreementQrCodeWorkflowInitiateHandlerMatchInfoSchema,
    SendFetchPreferenceMessageQueryStringSchema,
    SetDAPermissionMatchInfoSchema,
    SetDAPermissionQueryStringSchema,
    UpdateDaPersonalDataInWalletMatchInfoSchema,
    UpdateDaPersonalDataInWalletRequestSchema,
    UpdateDaPersonalDataInWalletResponseSchema,
    UpdateDataAgreementMatchInfoSchema,
    UpdateDataAgreementTemplateOpenAPISchema,
)
from mydata_did.v1_0.utils.util import str_to_bool

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Create and store data agreement template in wallet",
    responses={422: {"description": "Unprocessable Entity (invalid request payload)"}},
)
@querystring_schema(CreateOrUpdateDataAgreementInWalletQueryStringSchema())
@request_schema(CreateOrUpdateDataAgreementInWalletRequestSchema())
@response_schema(DataAgreementV1RecordResponseSchema(), 201)
async def create_and_store_data_agreement_in_wallet_v2(request: web.BaseRequest):
    """Create and store data agreement template in wallet."""

    # Request context
    context = request.app["request_context"]

    # Fetch request body
    data_agreement = await request.json()

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    # Fetch querystring params
    publish_flag = str_to_bool(
        clean_and_get_field_from_dict(request.query, "publish_flag")
    )
    existing_schema_id = clean_and_get_field_from_dict(
        request.query, "existing_schema_id"
    )

    try:

        # Create and store data agreement in wallet
        da_record = await manager.create_and_store_da_template_in_wallet(
            data_agreement=data_agreement,
            publish_flag=publish_flag,
            schema_id=existing_schema_id,
        )

        if not da_record:
            raise web.HTTPBadRequest(reason="Data agreement not created")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(da_record.serialize(), status=201)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Publish data agreement templates in the wallet",
    responses={400: {"description": "Bad Request (invalid request payload)"}},
)
@match_info_schema(PublishDataAgreementMatchInfoSchema())
@response_schema(DataAgreementV1RecordResponseSchema(), 200)
async def publish_data_agreement_handler(request: web.BaseRequest):
    """Publish data agreement template in the wallet."""

    # Request context
    context = request.app["request_context"]

    # Get path parameters
    template_id = request.match_info["template_id"]

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    try:

        # Publish data agreement in the wallet
        record = await manager.publish_da_template_in_wallet(template_id)

        if not record:
            raise web.HTTPBadRequest(reason="Data agreement not published")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize(), status=200)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Query data agreement templates in the wallet",
)
@querystring_schema(DataAgreementQueryStringSchema())
@response_schema(DataAgreementV1RecordResponseSchema(many=True), 200)
async def query_data_agreements_in_wallet(request: web.BaseRequest):
    """Query data agreement templates in the wallet."""

    # Request context
    context = request.app["request_context"]

    # Fetch query string parameters
    method_of_use = clean_and_get_field_from_dict(request.query, "method_of_use")
    template_id = clean_and_get_field_from_dict(request.query, "template_id")
    template_version = clean_and_get_field_from_dict(request.query, "template_version")
    delete_flag = clean_and_get_field_from_dict(request.query, "delete_flag")
    publish_flag = clean_and_get_field_from_dict(request.query, "publish_flag")
    latest_version_flag = clean_and_get_field_from_dict(
        request.query, "latest_version_flag"
    )
    third_party_data_sharing = clean_and_get_field_from_dict(
        request.query, "third_party_data_sharing"
    )
    page = clean_and_get_field_from_dict(request.query, "page")
    page = int(page) if page is not None else page
    page_size = clean_and_get_field_from_dict(request.query, "page_size")
    page_size = int(page_size) if page_size is not None else page_size

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    try:

        # Query data agreements in the wallet
        paginationResult = await manager.query_da_templates_in_wallet(
            template_id=template_id,
            delete_flag=delete_flag,
            method_of_use=method_of_use,
            publish_flag=publish_flag,
            latest_version_flag=latest_version_flag,
            template_version=template_version,
            third_party_data_sharing=third_party_data_sharing,
            page=page if page else 1,
            page_size=page_size if page_size else 10,
        )

    except (StorageError, BaseModelError, ValueError) as err:

        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(paginationResult._asdict())


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Update data agreement template in the wallet",
    responses={400: {"description": "Bad Request (invalid request payload)"}},
)
@match_info_schema(UpdateDataAgreementMatchInfoSchema())
@querystring_schema(UpdateDataAgreementTemplateOpenAPISchema())
@request_schema(CreateOrUpdateDataAgreementInWalletRequestSchema())
@response_schema(DataAgreementV1RecordResponseSchema(), 200)
async def update_data_agreement_in_wallet_v2(request: web.BaseRequest):
    """Update data agreement template in the wallet."""

    # Request context
    context = request.app["request_context"]

    # URL params
    template_id = request.match_info["template_id"]

    # Fetch request body
    data_agreement = await request.json()

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    # Fetch querystring params
    publish_flag = str_to_bool(
        clean_and_get_field_from_dict(request.query, "publish_flag")
    )
    existing_schema_id = clean_and_get_field_from_dict(
        request.query, "existing_schema_id"
    )

    try:
        # Update data agreement in the wallet
        record = await manager.update_and_store_da_template_in_wallet(
            template_id=template_id,
            data_agreement=data_agreement,
            publish_flag=publish_flag,
            schema_id=existing_schema_id,
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize(), status=200)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Delete data agreement template in the wallet",
    responses={
        204: {"description": "No Content (data agreement deleted)"},
        400: {"description": "Bad Request (invalid request payload)"},
    },
)
@match_info_schema(DeleteDataAgreementMatchInfoSchema())
async def delete_data_agreement_in_wallet(request: web.BaseRequest):
    """Delete data agreement template in the wallet."""

    # Request context
    context = request.app["request_context"]

    # URL params
    template_id = request.match_info["template_id"]

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    try:
        # Delete data agreement template in the wallet
        await manager.delete_da_template_in_wallet(template_id=template_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Query data agreement personal data in wallet",
)
@querystring_schema(QueryDaPersonalDataInWalletQueryStringSchema())
@response_schema(DataAgreementPersonalDataRecordSchema(many=True), 200)
async def query_da_personal_data_in_wallet(request: web.BaseRequest):
    """Query data agreement personal data in wallet."""

    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    # Fetch query string parameters
    method_of_use = clean_and_get_field_from_dict(request.query, "method_of_use")
    template_id = clean_and_get_field_from_dict(request.query, "template_id")
    third_party_data_sharing = clean_and_get_field_from_dict(
        request.query, "third_party_data_sharing"
    )
    page = clean_and_get_field_from_dict(request.query, "page")
    page = int(page) if page is not None else page
    page_size = clean_and_get_field_from_dict(request.query, "page_size")
    page_size = int(page_size) if page_size is not None else page_size

    try:

        # Query data agreement personal data in wallet
        paginationResult = await manager.query_pd_of_da_template_from_wallet(
            template_id=template_id,
            method_of_use=method_of_use,
            third_party_data_sharing=third_party_data_sharing,
            page=page if page else 1,
            page_size=page_size if page_size else 10,
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(paginationResult._asdict())


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Update personal data description in wallet.",
    responses={400: {"description": "Bad Request (invalid request payload)"}},
)
@match_info_schema(UpdateDaPersonalDataInWalletMatchInfoSchema())
@request_schema(UpdateDaPersonalDataInWalletRequestSchema())
@response_schema(UpdateDaPersonalDataInWalletResponseSchema(), 200)
async def update_da_personal_data_in_wallet(request: web.BaseRequest):
    """Update personal data description."""
    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    # URL params
    attribute_id = request.match_info["attribute_id"]

    # Request data
    body = await request.json()

    attribute_description = body.get("attribute_description")

    try:
        # Update data agreement personal data in wallet
        record = await manager.update_personal_data_description(
            attribute_id=attribute_id, desc=attribute_description
        )
    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Delete personal data in wallet",
    responses={
        204: {"description": "No Content (data agreement personal data deleted)"},
        400: {"description": "Bad Request (invalid request payload)"},
    },
)
@match_info_schema(DeleteDaPersonalDataInWalletMatchInfoSchema())
async def delete_da_personal_data_in_wallet(request: web.BaseRequest):
    """Delete personal data in wallet."""

    # Request context
    context = request.app["request_context"]

    # URL params
    attribute_id = request.match_info["attribute_id"]

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    try:

        await manager.delete_personal_data(attribute_id=attribute_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Generate Data Agreement QR code payload",
    responses={400: "Bad Request"},
)
@querystring_schema(GenerateDataAgreementQrCodePayloadQueryStringSchema())
@match_info_schema(DataAgreementQRCodeMatchInfoSchema())
@response_schema(GenerateDataAgreementQrCodePayloadResponseSchema(), 201)
async def generate_data_agreement_qr_code_payload(request: web.BaseRequest):
    # Get path parameters.
    template_id = request.match_info["template_id"]

    # Context.
    context = request.app["request_context"]

    # Query string params
    multi_use_flag = clean_and_get_field_from_dict(request.query, "multi_use")
    multi_use_flag = str_to_bool(multi_use_flag)

    # Initialise MyData DID Manager.
    manager = V2ADAManager(context)

    try:

        # Call the function.
        result = await manager.create_data_agreement_qr_code(
            template_id, multi_use_flag
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result, status=201)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Query Data Agreement QR code metadata records",
)
@match_info_schema(QueryDataAgreementQrCodeMetadataRecordsMatchInfoSchema())
@response_schema(QueryDataAgreementQRCodeMetadataRecordsResponseSchema(many=True))
async def query_data_agreement_qr_code_metadata_records_handler(
    request: web.BaseRequest,
):
    # Context.
    context = request.app["request_context"]

    # Path parameters
    template_id = request.match_info["template_id"]

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    try:
        # Call the function.
        result = await mgr.query_data_agreement_qr_codes(template_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result._asdict())


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Delete Data Agreement QR code record.",
    responses={
        204: {"description": "Success"},
    },
)
@match_info_schema(RemoveDataAgreementQrCodeMetadataRecordMatchInfoSchema())
async def remove_data_agreement_qr_code_metadata_record_handler(
    request: web.BaseRequest,
):

    # Context
    context = request.app["request_context"]

    # Fetch path parameters.
    template_id = request.match_info["template_id"]
    qr_id = request.match_info["qr_id"]

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    try:
        # Call the function.
        await mgr.delete_data_agreement_qr_code(template_id, qr_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Send data agreement qr code workflow initiate message to remote agent",
)
@match_info_schema(SendDataAgreementQrCodeWorkflowInitiateHandlerMatchInfoSchema())
async def send_data_agreements_qr_code_workflow_initiate_handler(
    request: web.BaseRequest,
):

    # Context.
    context = request.app["request_context"]

    # Fetch path parameters.

    connection_id = request.match_info["connection_id"]
    qr_id = request.match_info["qr_id"]

    # Initialise MyData DID Manager.
    mgr = V2ADAManager(context=context)

    try:

        # Call the function.
        await mgr.send_qr_code_initiate_message(qr_id, connection_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Fetch customer identification data agreement.",
)
async def fetch_customer_identification_da_handler(request: web.BaseRequest):
    """Fetch customer identification DA.

    Args:
        request (web.BaseRequest): Request.
    """

    # Context
    context = request.app["request_context"]

    # Initialise the manager
    mgr = DexaManager(context)

    # Call the function
    record = await mgr.fetch_customer_identification_data_agreement()

    return web.json_response(record.serialize() if record else {})


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Configure customer identification data agreement.",
)
@match_info_schema(ConfigureCustomerIdentificationDAMatchInfoSchema())
async def configure_customer_identification_da_handler(request: web.BaseRequest):
    """Configure customer identification DA.

    Args:
        request (web.BaseRequest): Request.
    """

    # Context
    context = request.app["request_context"]

    # Path parameters
    template_id = request.match_info["template_id"]

    # Initialise the manager
    mgr = DexaManager(context)

    # Call the function
    record = await mgr.configure_customer_identification_data_agreement(template_id)

    return web.json_response(record.serialize())


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Set permissions for data agreement.",
)
@match_info_schema(SetDAPermissionMatchInfoSchema())
@querystring_schema(SetDAPermissionQueryStringSchema())
async def set_da_permission_handler(request: web.BaseRequest):
    """Set DA permission handler.

    Args:
        request (web.BaseRequest): Request.
    """

    # Context
    context = request.app["request_context"]

    # Path parameters
    instance_id = request.match_info["instance_id"]

    # Query params
    state = clean_and_get_field_from_dict(request.query, "state")

    # Initialise the manager
    mgr = V2ADAManager(context)

    # Call the function
    await mgr.send_da_permissions_message(instance_id, state)

    return web.json_response({}, status=204)


@docs(
    tags=[TAGS_DATA_SUBJECT_FUNCTIONS_LABEL],
    summary="Send fetch preference message.",
)
@querystring_schema(SendFetchPreferenceMessageQueryStringSchema())
async def send_fetch_preference_message_handler(request: web.BaseRequest):
    """Send fetch preference message handler.

    Args:
        request (web.BaseRequest): Request.
    """

    # Context
    context = request.app["request_context"]

    # Query string params.
    connection_id = clean_and_get_field_from_dict(request.query, "connection_id")

    # Initialise the manager
    mgr = V2ADAManager(context)

    # Call the function
    res = await mgr.send_fetch_preference_message(connection_id)

    return web.json_response(res.serialize())
