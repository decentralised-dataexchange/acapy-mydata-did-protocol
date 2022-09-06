import json
import typing
import logging
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    querystring_schema,
    response_schema,
    match_info_schema,
)
from marshmallow import fields
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.error import StorageNotFoundError, StorageError
from aries_cloudagent.messaging.valid import (
    UUIDFour,
)
from aries_cloudagent.connections.models.connection_record import (
    ConnectionRecord,
)
from aries_cloudagent.protocols.connections.v1_0.manager import (
    ConnectionManagerError,
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from dexa_sdk.utils import clean_and_get_field_from_dict
from ..manager import ADAManager, ADAManagerError
from ..models.exchange_records.data_agreement_didcomm_transaction_record import (
    DataAgreementCRUDDIDCommTransaction,
)
from ..models.exchange_records.data_agreement_personal_data_record import (
    DataAgreementPersonalDataRecordSchema,
)
from ..utils.util import (
    str_to_bool,
)
from ..routes.maps.tag_maps import (
    TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL,
)

from .openapi import (
    ReadDataAgreementRequestSchema,
    DataAgreementCRUDDIDCommTransactionResponseSchema,
    DACRUDDIDCommTransactionRecordListQueryStringSchema,
    DataAgreementCRUDDIDCommTransactionRecordDeleteByIdMatchInfoSchema,
    DataAgreementV1RecordResponseSchema,
    DataAgreementQueryStringSchema,
    UpdateDataAgreementMatchInfoSchema,
    DeleteDataAgreementMatchInfoSchema,
    DataAgreementQRCodeMatchInfoSchema,
    GenerateDataAgreementQrCodePayloadResponseSchema,
    CreateOrUpdateDataAgreementInWalletQueryStringSchema,
    PublishDataAgreementMatchInfoSchema,
    QueryDaPersonalDataInWalletQueryStringSchema,
    UpdateDaPersonalDataInWalletMatchInfoSchema,
    UpdateDaPersonalDataInWalletRequestSchema,
    UpdateDaPersonalDataInWalletResponseSchema,
    DeleteDaPersonalDataInWalletMatchInfoSchema,
    QueryDataAgreementQrCodeMetadataRecordsMatchInfoSchema,
    QueryDataAgreementQrCodeMetadataRecordsQueryStringSchema,
    QueryDataAgreementQRCodeMetadataRecordsResponseSchema,
    RemoveDataAgreementQrCodeMetadataRecordMatchInfoSchema,
    Base64EncodeDataAgreementQrCodeMatchInfoSchema,
    SendDataAgreementQrCodeWorkflowInitiateHandlerMatchInfoSchema,
    SendReadAllDataAgreementTemplateMessageHandlerMatchInfoSchema,
    GenerateDataAgreementQrCodePayloadQueryStringSchema,
    CreateOrUpdateDataAgreementInWalletRequestSchema,
    UpdateDataAgreementTemplateOpenAPISchema
)

LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Send read data agreement message to Data Controller (remote agent)",
)
@request_schema(ReadDataAgreementRequestSchema())
@response_schema(DataAgreementCRUDDIDCommTransactionResponseSchema(), 200)
async def send_read_data_agreement(request: web.BaseRequest):
    """
    Send read-data-agreement message to the connection
    """

    # Request context
    context = request.app["request_context"]

    # Request payload
    body = await request.json()

    # Data agreement ID
    data_agreement_id = body.get("data_agreement_id")
    # Connection ID
    connection_id = body.get("connection_id")

    # Check if data agreement ID is provided
    if not data_agreement_id:
        raise web.HTTPBadRequest(reason="Data Agreement ID missing")
    # Check if connection ID is provided
    if not connection_id:
        raise web.HTTPBadRequest(reason="Connection ID missing")

    # API Response
    result = {}

    try:
        # Fetch connection record
        connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )

        # Check if connection is ready
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"ADA registry connection {connection_id} not ready"
            )

        # Initialise MyData DID Manager
        mydata_did_manager = ADAManager(context=context)
        # Send read-data-agreement message
        transaction_record: DataAgreementCRUDDIDCommTransaction = (
            await mydata_did_manager.send_read_data_agreement_message(
                connection_record=connection_record, data_agreement_id=data_agreement_id
            )
        )

        result = {
            "da_crud_didcomm_tx_id": transaction_record.da_crud_didcomm_tx_id,
            "thread_id": transaction_record.thread_id,
            "message_type": transaction_record.message_type,
            "messages_list": [
                json.loads(message) if isinstance(message, str) else message
                for message in transaction_record.messages_list
            ],
            "connection_id": transaction_record.connection_id,
        }

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result)


# List data agreement crud didcomm transactions from the wallet
@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="List data agreements crud didcomm transactions from the wallet",
)
@querystring_schema(DACRUDDIDCommTransactionRecordListQueryStringSchema())
@response_schema(DataAgreementCRUDDIDCommTransactionResponseSchema(many=True), 200)
async def list_data_agreements_crud_didcomm_transactions(request: web.BaseRequest):
    """
    List data agreements crud didcomm transactions from the wallet
    """
    # Request context
    context = request.app["request_context"]

    # Get query string parameters
    tag_filter = {}

    # Thread ID
    if "thread_id" in request.query and request.query["thread_id"] != "":
        tag_filter["thread_id"] = request.query["thread_id"]

    # Connection ID
    if "connection_id" in request.query and request.query["connection_id"] != "":
        tag_filter["connection_id"] = request.query["connection_id"]

    # Message type
    if "message_type" in request.query and request.query["message_type"] != "":
        tag_filter["message_type"] = request.query["message_type"]

    # Transactions list to be returned
    transactions = []
    try:

        # Fetch data agreements crud didcomm transactions from the wallet
        transactions: typing.List[
            DataAgreementCRUDDIDCommTransaction
        ] = await DataAgreementCRUDDIDCommTransaction.query(context, tag_filter)

        # Serialize transactions
        transactions = [
            {
                "da_crud_didcomm_tx_id": transaction.da_crud_didcomm_tx_id,
                "thread_id": transaction.thread_id,
                "message_type": transaction.message_type,
                "messages_list": [
                    json.loads(message) if isinstance(message, str) else message
                    for message in transaction.messages_list
                ],
                "connection_id": transaction.connection_id,
            }
            for transaction in transactions
        ]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(transactions)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Remove data agreement CRUD DIDComm transaction record by ID",
    responses={
        204: {"description": "Data agreement CRUD DIDComm transaction record removed"}
    },
)
@match_info_schema(DataAgreementCRUDDIDCommTransactionRecordDeleteByIdMatchInfoSchema())
async def data_agreement_crud_didcomm_transaction_records_delete_by_id(
    request: web.BaseRequest,
):
    """
    Request handler for removing data agreement CRUD DIDComm transaction record by ID
    """

    # Context
    context = request.app["request_context"]

    # Get path parameters
    da_crud_didcomm_tx_id = request.match_info["da_crud_didcomm_tx_id"]

    try:
        # Get the DIDComm transaction record
        transaction_record = await DataAgreementCRUDDIDCommTransaction.retrieve_by_id(
            context=context, record_id=da_crud_didcomm_tx_id
        )

        # Delete the DIDComm transaction record
        await transaction_record.delete_record(context)
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(None, status=204)


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
    publish_flag = str_to_bool(clean_and_get_field_from_dict(request.query, "publish_flag"))
    existing_schema_id = clean_and_get_field_from_dict(request.query, "existing_schema_id")

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
    latest_version_flag = clean_and_get_field_from_dict(request.query, "latest_version_flag")
    third_party_data_sharing = clean_and_get_field_from_dict(
        request.query, "third_party_data_sharing")
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
            page_size=page_size if page_size else 10
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
    publish_flag = str_to_bool(clean_and_get_field_from_dict(request.query, "publish_flag"))
    existing_schema_id = clean_and_get_field_from_dict(request.query, "existing_schema_id")

    try:
        # Update data agreement in the wallet
        record = await manager.update_and_store_da_template_in_wallet(
            template_id=template_id,
            data_agreement=data_agreement,
            publish_flag=publish_flag,
            schema_id=existing_schema_id
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
        await manager.delete_da_template_in_wallet(
            template_id=template_id
        )

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
        request.query, "third_party_data_sharing")
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
            page_size=page_size if page_size else 10
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
            attribute_id=attribute_id,
            desc=attribute_description
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

        await manager.delete_personal_data(
            attribute_id=attribute_id
        )

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
    data_agreement_id = request.match_info["data_agreement_id"]

    # Context.
    context = request.app["request_context"]

    multi_use = (
        False if "multi_use" not in request.query else request.query["multi_use"]
    )

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    try:

        # Call the function.

        result = await mydata_did_manager.construct_data_agreement_qr_code_payload(
            data_agreement_id=data_agreement_id, multi_use=multi_use
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result, status=201)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Query Data Agreement QR code metadata records",
)
@match_info_schema(QueryDataAgreementQrCodeMetadataRecordsMatchInfoSchema())
@querystring_schema(QueryDataAgreementQrCodeMetadataRecordsQueryStringSchema())
@response_schema(QueryDataAgreementQRCodeMetadataRecordsResponseSchema(many=True))
async def query_data_agreement_qr_code_metadata_records_handler(
    request: web.BaseRequest,
):
    # Context.
    context = request.app["request_context"]

    tag_filter = {"data_agreement_id": request.match_info["data_agreement_id"]}

    # qr id
    if "qr_id" in request.query and request.query["qr_id"] != "":
        tag_filter["qr_id"] = request.query["qr_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    try:

        # Call the function.

        result = await mydata_did_manager.query_data_agreement_qr_metadata_records(
            query_string=tag_filter
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


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
    data_agreement_id = request.match_info["data_agreement_id"]
    qr_id = request.match_info["qr_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    try:

        # Call the function.

        await mydata_did_manager.delete_data_agreement_qr_metadata_record(
            data_agreement_id=data_agreement_id, qr_id=qr_id
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Base64 encode data agreement qr code payload",
)
@match_info_schema(Base64EncodeDataAgreementQrCodeMatchInfoSchema())
async def base64_encode_data_agreement_qr_code_payload_handler(
    request: web.BaseRequest,
):

    # Context.
    context = request.app["request_context"]

    # Fetch path parameters.
    data_agreement_id = request.match_info["data_agreement_id"]
    qr_id = request.match_info["qr_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    result = {}
    try:

        # Call the function.

        base64_string = (
            await mydata_did_manager.base64_encode_data_agreement_qr_code_payload(
                data_agreement_id=data_agreement_id, qr_id=qr_id
            )
        )

        result = {"base64_string": base64_string}

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


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
    mydata_did_manager: ADAManager = ADAManager(context=context)

    try:

        # Call the function.

        await mydata_did_manager.send_data_agreement_qr_code_workflow_initiate_message(
            connection_id=connection_id, qr_id=qr_id
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


class GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadMatchInfoSchema(
    OpenAPISchema
):
    """Schema to match URL path parameters in generate firebase dynamic link for
    data agreement qr endpoint"""

    # Data agreement identifier.
    data_agreement_id = fields.Str(
        description="Data agreement identifier", example=UUIDFour.EXAMPLE, required=True
    )

    # Qr code identifier
    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=True
    )


class GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadResponseSchema(
    OpenAPISchema
):
    """Response schema for generate firebase dynamic link for data agreement qr endpoint"""

    # Firebase dynamic link
    firebase_dynamic_link = fields.Str(
        description="Firebase dynamic link",
        example="https://example.page.link/UVWXYZuvwxyz12345",
    )


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Generate firebase dynamic link for data agreement qr code payload.",
)
@match_info_schema(
    GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadMatchInfoSchema()
)
@response_schema(
    GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadResponseSchema(), 200
)
async def generate_firebase_dynamic_link_for_data_agreement_qr_code_payload_handler(
    request: web.BaseRequest,
):
    """Generate firebase dynamic link for data agreement qr code payload."""

    # Context.
    context = request.app["request_context"]

    # Fetch path parameters.
    data_agreement_id = request.match_info["data_agreement_id"]
    qr_id = request.match_info["qr_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    result = {}
    try:

        # Call the function.

        firebase_dynamic_link = \
            await mydata_did_manager.generate_firebase_dynamic_link_for_data_agreement_qr_payload(
                data_agreement_id=data_agreement_id, qr_id=qr_id
            )

        result = {"firebase_dynamic_link": firebase_dynamic_link}

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(
    tags=[TAGS_DATA_AGREEMENT_CORE_FUNCTIONS_LABEL],
    summary="Send read all data agreement template message to remote agent.",
    responses={
        200: {
            "description": "Success",
        }
    },
)
@match_info_schema(SendReadAllDataAgreementTemplateMessageHandlerMatchInfoSchema())
async def send_read_all_data_agreement_template_message_handler(
    request: web.BaseRequest,
):
    """Send read all data agreement template message to remote agent."""

    context = request.app["request_context"]
    connection_id = request.match_info["connection_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)
    try:
        # Call the function
        await mydata_did_manager.send_read_all_data_agreement_template_message(
            connection_id
        )

    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=200)
