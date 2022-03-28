import json
from nis import match
import os
import sys
import typing
import uuid
import logging
import jwt
import math

import validators

from aiohttp import web
from aiohttp import frozenlist
from aiohttp_apispec.decorators import request
from aiohttp.web_response import json_response
from aiohttp_apispec import docs, request_schema, querystring_schema, response_schema, match_info_schema, validation_middleware
from marshmallow import fields, validate, validates
from marshmallow.exceptions import ValidationError

from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.storage.error import StorageNotFoundError, StorageError
from aries_cloudagent.messaging.valid import INDY_DID, UUIDFour, UUID4, INDY_RAW_PUBLIC_KEY
from aries_cloudagent.protocols.problem_report.v1_0 import internal_error
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.indy import IndyStorage
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet
from aries_cloudagent.connections.models.connection_record import ConnectionRecord, ConnectionRecordSchema
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager, ConnectionManagerError
from aries_cloudagent.protocols.connections.v1_0.messages.connection_invitation import ConnectionInvitationSchema

from .manager import ADAManager, ADAManagerError
from .models.exchange_records.mydata_did_registry_didcomm_transaction_record import MyDataDIDRegistryDIDCommTransactionRecord, MyDataDIDRegistryDIDCommTransactionRecordSchema
from .models.exchange_records.data_agreement_didcomm_transaction_record import DataAgreementCRUDDIDCommTransaction, DataAgreementCRUDDIDCommTransactionSchema
from .models.exchange_records.data_agreement_record import DataAgreementV1Record, DataAgreementV1RecordSchema
from .models.exchange_records.data_agreement_personal_data_record import DataAgreementPersonalDataRecordSchema, DataAgreementPersonalDataRecord
from .models.exchange_records.auditor_didcomm_transaction_record import AuditorDIDCommTransactionRecord, AuditorDIDCommTransactionRecordSchema
from .models.data_agreement_model import (
    DataAgreementPersonalData,
    DataAgreementPersonalDataSchema,
    DataAgreementV1Schema,
    DataAgreementV1,
    DATA_AGREEMENT_V1_SCHEMA_CONTEXT,
    DataAgreementDataPolicySchema,
    DataAgreementDPIASchema
)
from .models.diddoc_model import MyDataDIDDocSchema
from .models.data_agreement_instance_model import DataAgreementInstanceSchema, DataAgreementInstance

from .utils.util import str_to_bool, bool_to_str, comma_separated_str_to_list, get_slices
from .utils.regex import MYDATA_DID
from .utils.jsonld.data_agreement import sign_data_agreement, verify_data_agreement, verify_data_agreement_with_proof_chain


LOGGER = logging.getLogger(__name__)

PAGINATION_PAGE_SIZE = 10


class SendCreateDIDMessageMatchInfoSchema(OpenAPISchema):
    """
    Send a create-did message to the MyData DID registry service.
    """
    did = fields.Str(description="did:sov identifier",
                     required=True, **INDY_DID)


class SendReadDIDMessageMatchInfoSchema(OpenAPISchema):
    """
    Send a read-did message to the MyData DID registry service.
    """
    did = fields.Str(description="did:mydata identifier",
                     required=True, **MYDATA_DID)


class SendDeleteDIDMessageMatchInfoSchema(OpenAPISchema):
    """
    Send a delete-did message to the MyData DID registry service.
    """
    did = fields.Str(description="did:mydata identifier",
                     required=True, **MYDATA_DID)


class MyDataDIDRegistryDIDCommTransactionRecordsRetrieveByIdMatchInfoSchema(OpenAPISchema):
    """
    Retrieve a transaction record by its identifier.
    """

    mydata_did_registry_didcomm_transaction_record_id = fields.Str(
        description="MyData DID registry didcomm transaction identifier", required=True, **UUID4
    )


class AuditorDIDCommTransactionRecordsRetrieveByIdMatchInfoSchema(OpenAPISchema):
    """
    Retrieve a transaction record by its identifier.
    """

    auditor_didcomm_transaction_record_id = fields.Str(
        description="Auditor didcomm transaction identifier", required=True, **UUID4
    )


class AuditorDIDCommTransactionRecordsDeleteByIdMatchInfoSchema(OpenAPISchema):
    """
    Delete a transaction record by its identifier.
    """

    auditor_didcomm_transaction_record_id = fields.Str(
        description="Auditor didcomm transaction identifier", required=True, **UUID4
    )


class MyDataDIDRegistryDIDCommTransactionRecordsDeleteByIdMatchInfoSchema(OpenAPISchema):
    """
    Delete a transaction record by its identifier.
    """

    mydata_did_registry_didcomm_transaction_record_id = fields.Str(
        description="MyData DID registry didcomm transaction identifier", required=True, **UUID4
    )


class DataAgreementCRUDDIDCommTransactionRecordDeleteByIdMatchInfoSchema(OpenAPISchema):
    """Delete a transaction record by its identifier."""

    da_crud_didcomm_tx_id = fields.Str(
        description="Data agreement CRUD didcomm transaction identifier", required=True, **UUID4
    )


class DummyDIDResolveRouteHandlerQueryStringSchema(OpenAPISchema):
    """
    Dummy DID resolve route handler query string schema.
    """
    did = fields.Str(description="did:mydata identifier")


class MyDataDIDRegistryDIDCommTransactionRecordListQueryStringSchema(OpenAPISchema):
    """
    Query string schema for listing MyData DID registry DIDComm transaction records.
    """

    # Connection identifier
    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    # Thread identifier
    thread_id = fields.UUID(
        description="Thread identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    # Message type
    message_type = fields.Str(
        description="Message type",
        required=False,
        validate=validate.OneOf(
            [
                getattr(MyDataDIDRegistryDIDCommTransactionRecord, m)
                for m in vars(MyDataDIDRegistryDIDCommTransactionRecord)
                if m.startswith("MESSAGE_TYPE_")
            ]
        ),
    )


class AuditorDIDCommTransactionRecordListQueryStringSchema(OpenAPISchema):
    """
    Query string schema for listing Auditor DIDComm transaction records.
    """

    # Connection identifier
    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    # Thread identifier
    thread_id = fields.UUID(
        description="Thread identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )


class DACRUDDIDCommTransactionRecordListQueryStringSchema(OpenAPISchema):
    """
    Query string schema for listing data agreement CRUD DIDComm transaction records.
    """

    # Connection identifier
    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    # Thread identifier
    thread_id = fields.UUID(
        description="Thread identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    # Message type
    message_type = fields.Str(
        description="Message type",
        required=False,
        validate=validate.OneOf(
            [
                getattr(DataAgreementCRUDDIDCommTransaction, m)
                for m in vars(DataAgreementCRUDDIDCommTransaction)
                if m.startswith("MESSAGE_TYPE_")
            ]
        ),
    )


class MyDataDIDRemoteRecordsQueryStringSchema(OpenAPISchema):
    """
    Query string schema for listing MyData DID remote records.
    """

    # Sovrin verkey
    sov_verkey = fields.Str(
        description="Sovrin verkey",
        required=False,
        **INDY_RAW_PUBLIC_KEY
    )

    # DID
    did = fields.Str(
        **MYDATA_DID,
        description="MyData decentralised identifier"
    )

    # Status
    status = fields.Str(
        description="MyData DID remote status",
        required=False,
        validate=validate.OneOf(
            [
                "active",
                "revoked"
            ]
        ),
    )


class MyDataDIDRemoteRecordResponseSchema(OpenAPISchema):
    """
    Response schema for MyData DID remote record.
    """

    did_doc = fields.Nested(
        MyDataDIDDocSchema,
        description="MyData DID document",
    )

    did = fields.Str(
        **MYDATA_DID,
        description="MyData decentralised identifier"
    )

    sov_verkey = fields.Str(
        description="Sovrin verkey",
        required=False,
        **INDY_RAW_PUBLIC_KEY
    )

    status = fields.Str(
        description="MyData DID remote status",
        required=False,
        validate=validate.OneOf(
            [
                "active",
                "revoked"
            ]
        ),
    )


class MyDataDIDRegistryDIDCommTransactionRecordListResponseSchema(OpenAPISchema):
    """
    Response schema for listing MyData DID registry DIDComm transaction records.
    """

    # Results of the query
    results = fields.List(
        fields.Nested(MyDataDIDRegistryDIDCommTransactionRecordSchema),
        description="MyData DID registry transaction records",
    )


class MyDataDIDRegistryMyDataDIDListQueryStringSchema(OpenAPISchema):
    """
    Query string schema for listing MyData DID records.
    """

    did = fields.Str(
        description="MyData decentralised identifier",
        required=False,
        **MYDATA_DID
    )

    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    status = fields.Str(
        description="MyData DID remote status",
        required=False,
        validate=validate.OneOf(
            [
                "active",
                "revoked"
            ]
        ),
    )


class MyDataDIDRegistryMyDataDIDListResponseSchema(OpenAPISchema):
    """
    Response schema for listing MyData DID records.
    """

    did = fields.Str(
        description="MyData decentralised identifier",
        required=False,
        **MYDATA_DID
    )

    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,
    )

    status = fields.Str(
        description="MyData DID remote status",
        required=False,
        validate=validate.OneOf(
            [
                "active",
                "revoked"
            ]
        ),
    )

    diddoc = fields.Nested(
        MyDataDIDDocSchema,
        description="MyData DID document",
    )

    version = fields.Str(
        description="MyData DID document version",
        required=False,
    )


class ReadDataAgreementRequestSchema(OpenAPISchema):
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True,
        example=UUIDFour.EXAMPLE,
    )
    connection_id = fields.UUID(
        description="Connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )


class DataAgreementQueryStringSchema(OpenAPISchema):
    """
    Query string schema for data agreements
    """

    method_of_use = fields.Str(
        description="Method of use",
        required=False,
        validate=validate.OneOf(
            [
                getattr(DataAgreementV1Record, m)
                for m in vars(DataAgreementV1Record)
                if m.startswith("METHOD_OF_USE_")
            ]
        ),
    )

    data_agreement_id = fields.Str(
        description="Data agreement identifier",
        required=False,
    )

    template_version = fields.Int(
        description="Data agreement template version",
    )

    delete_flag = fields.Bool(
        description="Delete flag to query deleted data agreements",
        required=False,
    )

    publish_flag = fields.Bool(
        description="Published flag to query published data agreements",
        required=False,
    )

    # Response fields
    include_fields = fields.Str(
        required=False,
        description="Comma separated fields to be included in the response.",
        example="connection_id,state,presentation_exchange_id",
    )

    page = fields.Int(
        required=False,
        description="Page number",
        example=1,
    )

    page_size = fields.Int(
        required=False,
        description="Page size",
        example=10,
    )


class UpdateDataAgreementMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the update data agreement endpoint
    """
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )


class DeleteDataAgreementMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the delete data agreement endpoint
    """
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )


class QueryDataAgreementVersionHistoryMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the query data agreement version history endpoint
    """
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )


class DataAgreementV1RecordResponseSchema(OpenAPISchema):
    """
    Schema for data agreement v1 record response
    """
    # Data agreement record identifier
    data_agreement_record_id = fields.Str(
        required=True,
        description="Data Agreement Record identifier",
        example=UUIDFour.EXAMPLE
    )

    # Data agreement identifier
    data_agreement_id = fields.Str(
        required=True,
        description="The unique identifier for the data agreement.",
        example=UUIDFour.EXAMPLE
    )

    # State of the data agreement.
    state = fields.Str(
        required=True,
        description="The state of the data agreement.",
        example=DataAgreementV1Record.STATE_PREPARATION,
        validate=validate.OneOf(
            [
                DataAgreementV1Record.STATE_PREPARATION,
            ]
        )
    )

    # Method of use for the data agreement.
    method_of_use = fields.Str(
        required=True,
        description="The method of use for the data agreement.",
        example="data-source",
        validate=validate.OneOf(
            [
                DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE,
                DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE,
            ]
        )
    )

    # Data agreement
    data_agreement = fields.Nested(
        DataAgreementV1Schema,
        required=True,
        description="The data agreement.",
    )

    # Production flag
    publish_flag = fields.Str(
        required=True,
        description="The production flag.",
        example="false",
        validate=validate.OneOf(
            [
                "true",
                "false",
            ]
        )
    )

    # Delete flag
    delete_flag = fields.Str(
        required=True,
        description="The delete flag.",
        example="false",
        validate=validate.OneOf(
            [
                "true",
                "false",
            ]
        )
    )


class CreateAndStoreDAPersonalDataInWalletRequestSchema(OpenAPISchema):

    """
    Schema for the create and store personal data in wallet request
    """

    @validates("attribute_name")
    def validate_attribute_name(self, attribute_name):
        """
        Validate attribute name
        """
        if len(attribute_name) < 3:
            raise ValidationError(
                "Attribute name must be at least 3 characters long")

    # Attribute name
    attribute_name = fields.Str(
        example="Name",
        description="Name of the attribute",
        required=True
    )

    # Attribute sensitive
    attribute_sensitive = fields.Bool(
        example=True,
        description="Sensitivity of the attribute",
        required=False
    )

    # Attribute category
    attribute_category = fields.Str(
        example="Personal",
        description="Category of the attribute",
        required=False
    )

    @validates("attribute_description")
    def validate_attribute_description(self, attribute_description):
        """
        Validate attribute description
        """
        if len(attribute_description) < 3:
            raise ValidationError(
                "Attribute description must be at least 3 characters long")

        if len(attribute_description) > 1000:
            raise ValidationError(
                "Attribute description must be at most 1000 characters long")

    # Attribute description
    attribute_description = fields.Str(
        example="Name of the user",
        description="Description of the attribute",
        required=False
    )


class QueryDAPersonalDataInWalletQueryStringSchema(OpenAPISchema):
    """
    Schema for the query personal data in wallet query string
    """

    attribute_sensitive = fields.Bool(
        description="Sensitivity of the attribute",
        required=False
    )

    attribute_category = fields.Str(
        description="Category of the attribute",
        required=False
    )


class ListDAPersonalDataCategoryFromWalletResponseSchema(OpenAPISchema):
    """
    Schema for the list personal data category from wallet response
    """

    # List of categories
    categories = fields.List(
        fields.Str(
            description="Category",
            example="Personal"
        ),
        description="List of categories",
        required=True
    )


class CreateOrUpdateDataAgreementPersonalDataRestrictionSchema(OpenAPISchema):
    """
    Schema for the create or update data agreement personal data restriction
    """

    schema_id = fields.Str(
        description="Schema identifier",
        example="WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0",
    )

    cred_def_id = fields.Str(
        description="Credential definition identifier",
        example="WgWxqztrNooG92RXvxSTWv:3:CL:20:tag",
    )


class CreateOrUpdateDataAgreementPersonalDataWithoutAttributeIdSchema(OpenAPISchema):
    """
    Personal data schema class
    """

    @validates("attribute_name")
    def validate_attribute_name(self, attribute_name):
        """
        Validate attribute name
        """
        if len(attribute_name) < 3:
            raise ValidationError(
                "Attribute name must be at least 3 characters long")

    # Attribute name
    attribute_name = fields.Str(
        example="Name",
        description="Name of the attribute",
        required=True
    )

    # Attribute description
    attribute_description = fields.Str(
        required=True,
        description="The description of the attribute.",
        example="Name of the customer"
    )

    restrictions = fields.List(
        fields.Nested(
            CreateOrUpdateDataAgreementPersonalDataRestrictionSchema),
        description="List of restrictions",
        required=False,
    )


class CreateOrUpdateDataAgreementPersonalDataRequestSchema(OpenAPISchema):
    """
    Schema for the create or update data agreement personal data request
    """

    attribute_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Attribute identifier",
        required=False,
    )

    restrictions = fields.List(
        fields.Nested(
            CreateOrUpdateDataAgreementPersonalDataRestrictionSchema),
        description="List of restrictions",
        required=False,
    )


class CreateOrUpdateDataAgreementInWalletRequestSchema(OpenAPISchema):
    """
    Schema for the create or update data agreement in wallet request
    """

    # Data agreement schema context i.e. which schema is used
    context = fields.Str(
        data_key="@context",
        example="https://raw.githubusercontent.com/decentralised-dataexchange/automated-data-agreements/main/interface-specs/data-agreement-schema/v1/data-agreement-schema-context.jsonld",
        description="Context of the schema",
        required=True
    )

    @validates("pii_controller_name")
    def validate_pii_controller_name(self, value):
        """
        Validate data agreement schema pii controller name
        """
        if len(value) < 3:
            raise ValidationError(
                f"PII controller name must be at least 3 characters long."
            )
        if len(value) > 100:
            raise ValidationError(
                f"PII controller name must be at most 100 characters long."
            )

    # Data agreement data controller name
    # i.e. Organization name of the data controller
    pii_controller_name = fields.Str(
        data_key="data_controller_name",
        example="Happy Shopping AB",
        description="PII controller name",
        required=True
    )

    @validates("pii_controller_url")
    def validate_pii_controller_url(self, value):
        """
        Validate data agreement schema pii controller url
        """
        if not validators.url(value):
            raise ValidationError(
                f"Provided PII controller URL is not valid."
            )

    # Data agreement data controller URL
    pii_controller_url = fields.Str(
        data_key="data_controller_url",
        example="https://www.happyshopping.com",
        description="PII controller URL"
    )

    @validates("usage_purpose")
    def validate_usage_purpose(self, value):
        """
        Validate data agreement schema usage purpose
        """
        if len(value) < 3:
            raise ValidationError(
                f"Usage purpose must be at least 3 characters long."
            )
        if len(value) > 100:
            raise ValidationError(
                f"Usage purpose must be at most 100 characters long."
            )

    # Data agreement usage purpose
    usage_purpose = fields.Str(
        data_key="purpose",
        example="Customized shopping experience",
        description="Usage purpose title",
        required=True
    )

    @validates("usage_purpose_description")
    def validate_usage_purpose_description(self, value):
        """
        Validate data agreement schema usage purpose description
        """
        if len(value) < 3:
            raise ValidationError(
                f"Usage purpose description must be at least 3 characters long."
            )
        if len(value) > 500:
            raise ValidationError(
                f"Usage purpose description must be at most 500 characters long."
            )

    # Data agreement usage purpose description
    usage_purpose_description = fields.Str(
        data_key="purpose_description",
        example="Collecting user data for offering custom tailored shopping experience",
        description="Usage purpose description",
        required=True
    )

    # Data agreement legal basis
    legal_basis = fields.Str(
        data_key="lawful_basis",
        example="consent",
        description="Legal basis of processing",
        required=True,
        validate=validate.OneOf(
            [
                "consent",
                "legal_obligation",
                "contract",
                "vital_interest",
                "public_task",
                "legitimate_interest",

            ]
        )
    )

    # Data agreement method of use (i.e. how the data is used)
    # 2 method of use: "data-source" and "data-using-service"
    method_of_use = fields.Str(
        data_key="method_of_use",
        example="data-using-service",
        description="Method of use (or data exchange mode)",
        required=True,
        validate=validate.OneOf(
            [
                "data-source",
                "data-using-service",

            ]
        )
    )

    # Data agreement data policy
    data_policy = fields.Nested(DataAgreementDataPolicySchema, required=True)

    # Data agreement personal data (attributes)
    personal_data = fields.List(
        fields.Nested(CreateOrUpdateDataAgreementPersonalDataRequestSchema),
        required=True
    )

    # Data agreement DPIA metadata
    dpia = fields.Nested(DataAgreementDPIASchema, required=False)


class CreateOrUpdateDataAgreementInWalletRequestSchemaV2(CreateOrUpdateDataAgreementInWalletRequestSchema):
    # Data agreement personal data (attributes)
    personal_data = fields.List(
        fields.Nested(
            CreateOrUpdateDataAgreementPersonalDataWithoutAttributeIdSchema),
        required=True
    )


class DataAgreementCRUDDIDCommTransactionResponseSchema(OpenAPISchema):
    """
    Schema for the data agreement CRUD DID comm transaction response
    """

    # Transaction identifier
    da_crud_didcomm_tx_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Data agreement CRUD DIDComm transaction identifier",
        required=False,
    )

    # Thread identifier
    thread_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Thread identifier",
        required=False,
    )

    # Message type
    message_type = fields.Str(
        example="read-data-agreement",
        description="Message type",
        required=False,
    )

    # Message list
    messages_list = fields.List(
        fields.Str(),
        description="List of messages",
        required=False,
    )

    # Connection identifier
    connection_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Connection identifier",
        required=False,
    )


class MarkExistingConnectionAsMyDataDIDRegistryMatchInfoSchema(OpenAPISchema):
    """
    Schema for the mark existing connection as my data DID registry match info
    """

    connection_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Connection identifier",
        required=True
    )


class MarkExistingConnectionAsAuditorMatchInfoSchema(OpenAPISchema):
    """
    Schema for the mark existing connection as auditor match info
    """

    connection_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Connection identifier",
        required=True
    )


class QueryDataAgreementInstanceQueryStringSchema(OpenAPISchema):
    """
    Schema for the query data agreement instance query string
    """

    data_agreement_template_id = fields.Str(
        description="Data agreement template identifier", required=False,
        example=UUIDFour.EXAMPLE,
    )

    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=False,
        example=UUIDFour.EXAMPLE,
    )

    method_of_use = fields.Str(
        data_key="method_of_use",
        example="data-using-service",
        description="Method of use (or data exchange mode)",
        required=False,
        validate=validate.OneOf(
            [
                "data-source",
                "data-using-service",

            ]
        )
    )

    data_exchange_record_id = fields.Str(
        description="Data exchange record identifier", required=False,
        example=UUIDFour.EXAMPLE,
    )


class AuditorSendDataAgreementVerifyRequestMatchInfoSchema(OpenAPISchema):
    """
    Schema to send data agreement verify request to the auditor 
    """

    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True,
        example=UUIDFour.EXAMPLE,
    )


class DataAgreementQRCodeMatchInfoSchema(OpenAPISchema):
    """
    Schema for data agreement QR code match info
    """

    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True,
        example=UUIDFour.EXAMPLE,
    )


class DataAgreementQRCodeInvitationSchema(OpenAPISchema):
    """Schema for connection invitation details inside in data agreement qr code payload."""

    service_endpoint = fields.Str(
        description="Service endpoint", example="http://localhost:8080/")
    recipient_key = fields.Str(
        description="Recipient key", **INDY_RAW_PUBLIC_KEY)


class GenerateDataAgreementQrCodePayloadResponseSchema(OpenAPISchema):
    """
    Schema for Data Agreement QR code payload
    """

    qr_id = fields.Str(description="QR code ID",  **UUID4)
    connection_id = fields.Str(description="Connection ID", **UUID4)
    invitation = fields.Nested(DataAgreementQRCodeInvitationSchema(
    ), description="Connection invitation information")


@docs(tags=["Data Agreement - MyData DID Operations"], summary="Fetch MyData DID registry transaction records")
@querystring_schema(MyDataDIDRegistryDIDCommTransactionRecordListQueryStringSchema())
@response_schema(MyDataDIDRegistryDIDCommTransactionRecordListResponseSchema(), 200)
async def mydata_did_registry_didcomm_transaction_records_list(request: web.BaseRequest):
    """
    Request handler for fetching MyData DID registry transaction records
    """

    # Context
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

    results = []

    try:
        # Get the list of DIDComm transaction records
        records = await MyDataDIDRegistryDIDCommTransactionRecord.query(context, tag_filter)

        # Convert to response format
        for record in records:
            temp_record = record.serialize()
            temp_messages_list = []

            for message in temp_record.get("messages_list", []):
                temp_messages_list.append(
                    json.loads(message)
                )

            temp_record["messages_list"] = temp_messages_list

            results.append(temp_record)

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["Data Agreement - MyData DID Operations"], summary="Fetch MyData DID registry DIDComm transaction record by ID")
@match_info_schema(MyDataDIDRegistryDIDCommTransactionRecordsRetrieveByIdMatchInfoSchema())
@response_schema(MyDataDIDRegistryDIDCommTransactionRecordSchema(), 200)
async def mydata_did_registry_didcomm_transaction_records_retreive_by_id(request: web.BaseRequest):
    """
    Request handler for fetching MyData DID registry DIDComm transaction record by ID
    """

    # Context
    context = request.app["request_context"]

    # Get path parameters
    mydata_did_registry_didcomm_transaction_record_id = request.match_info[
        "mydata_did_registry_didcomm_transaction_record_id"]

    result = {}
    try:
        # Get the DIDComm transaction record
        mydata_did_mydata_did_registry_didcomm_transaction_record = await MyDataDIDRegistryDIDCommTransactionRecord.retrieve_by_id(
            context=context,
            record_id=mydata_did_registry_didcomm_transaction_record_id
        )

        # Convert to response format
        temp_record = mydata_did_mydata_did_registry_didcomm_transaction_record.serialize()
        temp_messages_list = []
        for message in temp_record.get("messages_list", []):
            temp_messages_list.append(
                json.loads(message)
            )

            temp_record["messages_list"] = temp_messages_list

        result = temp_record

    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(
    tags=["Data Agreement - MyData DID Operations"],
    summary="Remove MyData DID registry DIDComm transaction record by ID",
    responses={
        204: {
            "description": "MyData DID registry DIDComm transaction record removed"
        }
    }
)
@match_info_schema(MyDataDIDRegistryDIDCommTransactionRecordsDeleteByIdMatchInfoSchema())
async def mydata_did_registry_didcomm_transaction_records_delete_by_id(request: web.BaseRequest):
    """
    Request handler for removing MyData DID registry DIDComm transaction record by ID
    """

    # Context
    context = request.app["request_context"]

    # Get path parameters
    mydata_did_registry_didcomm_transaction_record_id = request.match_info[
        "mydata_did_registry_didcomm_transaction_record_id"]

    try:
        # Get the DIDComm transaction record
        mydata_did_mydata_did_registry_didcomm_transaction_record = await MyDataDIDRegistryDIDCommTransactionRecord.retrieve_by_id(
            context=context,
            record_id=mydata_did_registry_didcomm_transaction_record_id
        )

        # Delete the DIDComm transaction record
        await mydata_did_mydata_did_registry_didcomm_transaction_record.delete_record(context)
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(None, status=204)


@docs(tags=["Data Agreement - MyData DID Operations"], summary="Send create-did didcomm message to MyData DID registry")
@match_info_schema(SendCreateDIDMessageMatchInfoSchema())
async def send_create_did_message_to_mydata_did_registry(request: web.BaseRequest):
    """
    Request handler for sending create-did didcomm message to MyData DID registry
    """

    # Context
    context = request.app["request_context"]

    # did:sov identifier
    did = request.match_info["did"]

    result = {}

    try:
        # Initialize MyData DID manager
        mydata_did_manager = ADAManager(context=context)

        # Send create-did message to MyData DID registry
        transaction_record = await mydata_did_manager.send_create_did_message(did)

        if transaction_record:
            # Serialize transaction record
            temp_record = transaction_record.serialize()
            temp_messages_list = []
            for message in temp_record.get("messages_list", []):
                temp_messages_list.append(
                    json.loads(message)
                )

                temp_record["messages_list"] = temp_messages_list

            result = temp_record
        else:
            raise web.HTTPInternalServerError(
                reason="Failed to send create-did message")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(tags=["Data Agreement - MyData DID Operations"], summary="Send read-did didcomm message to MyData DID registry")
@match_info_schema(SendReadDIDMessageMatchInfoSchema())
async def send_read_did_message_to_mydata_did_registry(request: web.BaseRequest):
    """
    Request handler for sending read-did didcomm message to MyData DID registry
    """

    # Context
    context = request.app["request_context"]

    # did:mydata identifier
    did = request.match_info["did"]

    result = {}

    try:

        # Initialize MyData DID manager
        mydata_did_manager = ADAManager(context=context)

        # Send read-did message to MyData DID registry
        transaction_record = await mydata_did_manager.send_read_did_message(did=did)

        if transaction_record:
            temp_record = transaction_record.serialize()
            temp_messages_list = []
            for message in temp_record.get("messages_list", []):
                temp_messages_list.append(
                    json.loads(message)
                )

                temp_record["messages_list"] = temp_messages_list

            result = temp_record

        else:
            raise web.HTTPInternalServerError(
                reason="Failed to send read-did message")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(tags=["Data Agreement - MyData DID Operations"], summary="Send delete-did message")
@match_info_schema(SendDeleteDIDMessageMatchInfoSchema())
async def send_delete_did_message_to_mydata_did_registry(request: web.BaseRequest):
    """
    Request handler for sending delete-did didcomm message to MyData DID registry
    """

    # Context
    context = request.app["request_context"]

    # did:mydata identifier
    did = request.match_info["did"]

    result = {}

    try:
        # Initialize MyData DID manager
        mydata_did_manager = ADAManager(context=context)

        # Send delete-did message to MyData DID registry
        transaction_record = await mydata_did_manager.send_delete_did_message(did=did)

        if transaction_record:
            temp_record = transaction_record.serialize()
            temp_messages_list = []
            for message in temp_record.get("messages_list", []):
                temp_messages_list.append(
                    json.loads(message)
                )

                temp_record["messages_list"] = temp_messages_list

            result = temp_record
        else:
            raise web.HTTPInternalServerError(
                reason="Failed to send delete-did message")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(tags=["Data Agreement - MyData DID Registry Admin Functions"], summary="Fetch all registered MyData DIDs")
@querystring_schema(MyDataDIDRegistryMyDataDIDListQueryStringSchema())
@response_schema(MyDataDIDRegistryMyDataDIDListResponseSchema(many=True), 200)
async def mydata_did_registry_mydata_did_list(request: web.BaseRequest):
    """
    Request handler for fetching all registered MyData DIDs
    """

    # Context
    context = request.app["request_context"]

    # Query string parameters
    tag_filter = {}
    if "did" in request.query and request.query["did"] != "":
        tag_filter["did"] = request.query["did"]

    if "connection_id" in request.query and request.query["connection_id"] != "":
        tag_filter["connection_id"] = request.query["connection_id"]

    if "status" in request.query and request.query["status"] != "":
        tag_filter["status"] = request.query["status"]

    results = []

    try:
        # Storage
        storage: IndyStorage = await context.inject(BaseStorage)

        # Search remote records
        remote_records: StorageRecord = await storage.search_records(
            type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REGISTRY_DID_INFO,
            tag_query=tag_filter
        ).fetch_all()

        for remote_record in remote_records:
            results.append({
                "did": remote_record.tags["did"],
                "connection_id": remote_record.tags["connection_id"],
                "status": remote_record.tags["status"],
                "version": remote_record.tags["version"],
                "diddoc": json.loads(remote_record.value),
            })

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(results)


@docs(tags=["Data Agreement - MyData DID Operations"], summary="Fetch MyData DID remote records.")
@querystring_schema(MyDataDIDRemoteRecordsQueryStringSchema())
@response_schema(MyDataDIDRemoteRecordResponseSchema(many=True), 200)
async def mydata_did_remote_records_list(request: web.BaseRequest):
    """
    Request handler for fetching MyData DID remote records
    """

    # Context
    context = request.app["request_context"]

    # Query string parameters
    tag_filter = {}
    if "did" in request.query and request.query["did"] != "":
        tag_filter["did"] = request.query["did"]

    if "sov_verkey" in request.query and request.query["sov_verkey"] != "":
        tag_filter["sov_verkey"] = request.query["sov_verkey"]

    if "status" in request.query and request.query["status"] != "":
        tag_filter["status"] = request.query["status"]

    results = []

    try:
        # Storage
        storage: IndyStorage = await context.inject(BaseStorage)

        # Search remote records
        remote_records: StorageRecord = await storage.search_records(
            type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REMOTE,
            tag_query=tag_filter
        ).fetch_all()

        for remote_record in remote_records:
            results.append({
                "did": remote_record.tags.get("did"),
                "sov_verkey": remote_record.tags.get("sov_verkey"),
                "status": remote_record.tags.get("status"),
                "diddoc": json.loads(remote_record.value)
            })

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(results)


@docs(tags=["Data Agreement - Core Functions"], summary="Send read data agreement message to Data Controller (remote agent)")
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
        connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)

        # Check if connection is ready
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"ADA registry connection {connection_id} not ready")

        # Initialise MyData DID Manager
        mydata_did_manager = ADAManager(context=context)
        # Send read-data-agreement message
        transaction_record: DataAgreementCRUDDIDCommTransaction = await mydata_did_manager.send_read_data_agreement_message(connection_record=connection_record, data_agreement_id=data_agreement_id)

        result = {
            "da_crud_didcomm_tx_id": transaction_record.da_crud_didcomm_tx_id,
            "thread_id": transaction_record.thread_id,
            "message_type": transaction_record.message_type,
            "messages_list": [json.loads(message) if isinstance(message, str) else message for message in transaction_record.messages_list],
            "connection_id": transaction_record.connection_id,
        }

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(result)


# List data agreement crud didcomm transactions from the wallet
@docs(tags=["Data Agreement - Core Functions"], summary="List data agreements crud didcomm transactions from the wallet")
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
        transactions: typing.List[DataAgreementCRUDDIDCommTransaction] = await DataAgreementCRUDDIDCommTransaction.query(
            context,
            tag_filter
        )

        # Serialize transactions
        transactions = [
            {
                "da_crud_didcomm_tx_id": transaction.da_crud_didcomm_tx_id,
                "thread_id": transaction.thread_id,
                "message_type": transaction.message_type,
                "messages_list": [json.loads(message) if isinstance(message, str) else message for message in transaction.messages_list],
                "connection_id": transaction.connection_id,
            }
            for transaction in transactions
        ]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(transactions)


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Remove data agreement CRUD DIDComm transaction record by ID",
    responses={
        204: {
            "description": "Data agreement CRUD DIDComm transaction record removed"
        }
    }
)
@match_info_schema(DataAgreementCRUDDIDCommTransactionRecordDeleteByIdMatchInfoSchema())
async def data_agreement_crud_didcomm_transaction_records_delete_by_id(request: web.BaseRequest):
    """
    Request handler for removing data agreement CRUD DIDComm transaction record by ID
    """

    # Context
    context = request.app["request_context"]

    # Get path parameters
    da_crud_didcomm_tx_id = request.match_info[
        "da_crud_didcomm_tx_id"]

    try:
        # Get the DIDComm transaction record
        transaction_record = await DataAgreementCRUDDIDCommTransaction.retrieve_by_id(
            context=context,
            record_id=da_crud_didcomm_tx_id
        )

        # Delete the DIDComm transaction record
        await transaction_record.delete_record(context)
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(None, status=204)


class CreateOrUpdateDataAgreementInWalletQueryStringSchema(OpenAPISchema):
    """Query string schema for create data agreement handler"""

    draft = fields.Boolean(
        description="draft mode",
        required=False,
        example=False
    )

    existing_schema_id = fields.Str(
        description="Existing schema identifier",
        required=False,
        example="issuer_did:1:schema:1"
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Create and store data agreement in wallet (v2)",
    responses={
        422: {
            "description": "Unprocessable Entity (invalid request payload)"
        }
    }
)
@querystring_schema(CreateOrUpdateDataAgreementInWalletQueryStringSchema())
@request_schema(CreateOrUpdateDataAgreementInWalletRequestSchemaV2())
@response_schema(DataAgreementV1RecordResponseSchema(), 201)
async def create_and_store_data_agreement_in_wallet_v2(request: web.BaseRequest):
    """
    Create and store data agreement in wallet. (v2)

    This endpoint is used to create and store data agreement in wallet.
    Request body should contain data agreement details.
    Response body will contain data agreement details along with data agreement ID and version.
    """

    # Request context
    context = request.app["request_context"]

    # Fetch request body
    data_agreement = await request.json()

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # Fetch querystring params
    draft = False
    existing_schema_id = None

    if "draft" in request.query and request.query["draft"] != "":
        draft = str_to_bool(request.query["draft"])

    if "existing_schema_id" in request.query and request.query["existing_schema_id"] != "":
        existing_schema_id = request.query["existing_schema_id"]

    try:

        # Create and store data agreement in wallet
        (data_agreement_v2_record, data_agreement_v2_dict) = await mydata_did_manager.create_data_agreement_and_personal_data_records(
            data_agreement=data_agreement,
            draft=draft,
            existing_schema_id=existing_schema_id,
        )

        if not data_agreement_v2_record:
            raise web.HTTPBadRequest(reason="Data agreement not created")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(data_agreement_v2_dict, status=201)


class PublishDataAgreementMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the publish data agreement endpoint
    """
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Publish data agreement in the wallet",
    responses={
        400: {
            "description": "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(PublishDataAgreementMatchInfoSchema())
@response_schema(DataAgreementV1RecordResponseSchema(), 200)
async def publish_data_agreement_handler(request: web.BaseRequest):
    """
    Publish data agreement in the wallet.

    This endpoint is used to publish data agreement in the wallet.
    """

    # Request context
    context = request.app["request_context"]

    # Get path parameters
    data_agreement_id = request.match_info["data_agreement_id"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:

        # Publish data agreement in the wallet
        (data_agreement_v1_record, data_agreement_dict) = await mydata_did_manager.publish_data_agreement_in_wallet(data_agreement_id)

        if not data_agreement_v1_record:
            raise web.HTTPBadRequest(reason="Data agreement not published")

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(data_agreement_dict, status=200)


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Query data agreements in the wallet",
)
@querystring_schema(DataAgreementQueryStringSchema())
@response_schema(DataAgreementV1RecordResponseSchema(many=True), 200)
async def query_data_agreements_in_wallet(request: web.BaseRequest):
    """
    Query data agreements in the wallet.

    This endpoint is used to query data agreements in the wallet.
    Response body will contain data agreements.
    """

    # Request context
    context = request.app["request_context"]

    tag_filter = {}

    # Fetch query string parameters
    if "method_of_use" in request.query and request.query["method_of_use"] != "":
        tag_filter["method_of_use"] = request.query["method_of_use"]

    if "data_agreement_id" in request.query and request.query["data_agreement_id"] != "":
        tag_filter["data_agreement_id"] = request.query["data_agreement_id"]

    if "template_version" in request.query and request.query["template_version"] != "":
        tag_filter["template_version"] = request.query["template_version"]

    if "delete_flag" in request.query and request.query["delete_flag"] != "":
        tag_filter["delete_flag"] = bool_to_str(
            str_to_bool(request.query["delete_flag"]))

    if "publish_flag" in request.query and request.query["publish_flag"] != "":
        tag_filter["publish_flag"] = bool_to_str(
            str_to_bool(request.query["publish_flag"]))

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # Pagination parameters
    pagination = {
        "totalCount": 0,
        "page": 0,
        "pageSize": PAGINATION_PAGE_SIZE,
        "totalPages": 0,
    }

    try:

        # Fields to be included in the response.
        include_fields = request.query.get("include_fields")
        include_fields = comma_separated_str_to_list(
            include_fields) if include_fields else None

        # Query data agreements in the wallet
        (data_agreement_records, resp_da_list) = await mydata_did_manager.query_data_agreements_in_wallet(tag_filter=tag_filter, include_fields=include_fields)

        # Page size from request.
        page_size = int(request.query.get("page_size", PAGINATION_PAGE_SIZE))
        pagination["pageSize"] = page_size

        # Total number of records
        pagination["totalCount"] = len(resp_da_list)

        # Total number of pages.
        pagination["totalPages"] = math.ceil(
            pagination["totalCount"] / pagination["pageSize"])

        # Pagination parameters
        page = request.query.get("page")
        if page:
            page = int(page)
            pagination["page"] = page

            lower, upper = get_slices(page, pagination["pageSize"])

            resp_da_list = resp_da_list[lower:upper]

    except (StorageError, BaseModelError, ValueError) as err:

        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({
        "results": resp_da_list,
        "pagination": pagination if page else {},
    })


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Update data agreement in the wallet (v2)",
    responses={
        400: {
            "description": "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(UpdateDataAgreementMatchInfoSchema())
@querystring_schema(CreateOrUpdateDataAgreementInWalletQueryStringSchema())
@request_schema(CreateOrUpdateDataAgreementInWalletRequestSchemaV2())
@response_schema(DataAgreementV1RecordResponseSchema(), 201)
async def update_data_agreement_in_wallet_v2(request: web.BaseRequest):
    """
    Update data agreement in the wallet. (v2)
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    data_agreement_id = request.match_info["data_agreement_id"]

    # Fetch request body
    data_agreement = await request.json()

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # Fetch querystring params
    draft = False
    existing_schema_id = None

    if "draft" in request.query and request.query["draft"] != "":
        draft = str_to_bool(request.query["draft"])

    if "existing_schema_id" in request.query and request.query["existing_schema_id"] != "":
        existing_schema_id = request.query["existing_schema_id"]

    try:
        # Update data agreement in the wallet
        (data_agreement_v2_record, data_agreement_v2_dict) = await mydata_did_manager.update_data_agreement_and_personal_data_records(
            data_agreement_id=data_agreement_id,
            data_agreement=data_agreement,
            existing_schema_id=existing_schema_id,
            draft=draft
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(data_agreement_v2_dict)


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Delete data agreement in the wallet",
    responses={
        204: {
            "description": "No Content (data agreement deleted)"
        },
        400: {
            "description": "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(DeleteDataAgreementMatchInfoSchema())
async def delete_data_agreement_in_wallet(request: web.BaseRequest):
    """
    Delete data agreement in the wallet.
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    data_agreement_id = request.match_info["data_agreement_id"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Delete data agreement in the wallet
        await mydata_did_manager.delete_data_agreement_in_wallet(data_agreement_id=data_agreement_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Query version history of a data agreement",
    responses={
        400: {
            "description": "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(QueryDataAgreementVersionHistoryMatchInfoSchema())
@response_schema(DataAgreementV1RecordResponseSchema(many=True), 200)
async def query_data_agreement_version_history(request: web.BaseRequest):
    """
    Query version history of a data agreement.
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    data_agreement_id = request.match_info["data_agreement_id"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:

        # Query version history of a data agreement
        (data_agreement_version_history_records, data_agreement_dict_list) = await mydata_did_manager.query_data_agreement_version_history(data_agreement_id=data_agreement_id)
    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(data_agreement_dict_list)


class QueryDaPersonalDataInWalletQueryStringSchema(OpenAPISchema):

    attribute_id = fields.Str(
        required=False,
        description="Personal Data ID",
        example=UUIDFour.EXAMPLE
    )

    page = fields.Int(
        required=False,
        description="Page number",
        example=1,
    )

    page_size = fields.Int(
        required=False,
        description="Page size",
        example=10,
    )

    method_of_use = fields.Str(
        required=False,
        description="Method of use",
        example="data-using-service",
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Query data agreement personal data in wallet",
)
@querystring_schema(QueryDaPersonalDataInWalletQueryStringSchema())
@response_schema(DataAgreementPersonalDataRecordSchema(many=True), 200)
async def query_da_personal_data_in_wallet(request: web.BaseRequest):
    """
    Query data agreement personal data in wallet.
    """

    # Request context
    context = request.app["request_context"]
    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    personal_data_id = None
    if "attribute_id" in request.query and request.query["attribute_id"] != "":
        personal_data_id = request.query["attribute_id"]

    method_of_use = None
    if "method_of_use" in request.query and request.query["method_of_use"] != "":
        method_of_use = request.query["method_of_use"]

    # Pagination parameters
    pagination = {
        "totalCount": 0,
        "page": 0,
        "pageSize": PAGINATION_PAGE_SIZE,
        "totalPages": 0,
    }

    try:

        # Query data agreement personal data in wallet
        results = await mydata_did_manager.query_da_personal_data_in_wallet(
            personal_data_id=personal_data_id,
            method_of_use=method_of_use
        )

        # Page size from request.
        page_size = int(request.query.get("page_size", PAGINATION_PAGE_SIZE))
        pagination["pageSize"] = page_size

        # Total number of records
        pagination["totalCount"] = len(results)

        # Total number of pages.
        pagination["totalPages"] = math.ceil(
            pagination["totalCount"] / pagination["pageSize"])

        # Pagination parameters
        page = request.query.get("page")

        if page:
            page = int(page)
            pagination["page"] = page

            lower, upper = get_slices(page, pagination["pageSize"])

            results = results[lower:upper]

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({
        "results": results,
        "pagination": pagination if page else {}
    })


class UpdateDaPersonalDataInWalletMatchInfoSchema(OpenAPISchema):

    attribute_id = fields.Str(
        required=True,
        description="Personal data identifier",
        example=UUIDFour.EXAMPLE
    )


class UpdateDaPersonalDataInWalletRequestSchema(OpenAPISchema):
    attribute_description = fields.Str(
        description="Attribute description", example="Age of the patient", required=True)


class UpdateDaPersonalDataInWalletResponseSchema(OpenAPISchema):

    attribute_id = fields.Str(
        description="Attribute ID", example=UUIDFour.EXAMPLE)
    attribute_name = fields.Str(description="Attribute name", example="Name")
    attribute_description = fields.Str(
        description="Attribute description", example="Name of the patient")
    data_agreement_template_id = fields.Str(
        description="Data Agreement Template ID", example=UUIDFour.EXAMPLE)
    data_agreement_template_version = fields.Integer(
        description="Data Agreement Template version", example=1)
    created_at = fields.Integer(
        description="Created at (Epoch time in seconds)", example=1578012800)
    updated_at = fields.Integer(
        description="Updated at (Epoch time in seconds)", example=1578012800)


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Update data agreement personal data in wallet",
    responses={
        400: {
            "description":  "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(UpdateDaPersonalDataInWalletMatchInfoSchema())
@request_schema(UpdateDaPersonalDataInWalletRequestSchema())
@response_schema(UpdateDaPersonalDataInWalletResponseSchema(), 200)
async def update_da_personal_data_in_wallet(request: web.BaseRequest):
    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    # URL params
    personal_data_id = request.match_info["attribute_id"]

    # Request data
    body = await request.json()

    attribute_description = body.get("attribute_description")

    try:

        # Update data agreement personal data in wallet
        (_, personal_data_dict) = await mydata_did_manager.update_personal_data_description(
            personal_data_id=personal_data_id,
            updated_description=attribute_description
        )

    except ADAManagerError as err:

        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(personal_data_dict)


class DeleteDaPersonalDataInWalletMatchInfoSchema(OpenAPISchema):

    attribute_id = fields.Str(
        required=True,
        description="Personal data identifier",
        example=UUIDFour.EXAMPLE
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Delete data agreement personal data in wallet",
    responses={
        204: {
            "description": "No Content (data agreement personal data deleted)"
        },
        400: {
            "description":  "Bad Request (invalid request payload)"
        }
    }
)
@match_info_schema(DeleteDaPersonalDataInWalletMatchInfoSchema())
async def delete_da_personal_data_in_wallet(request: web.BaseRequest):

    # Request context
    context = request.app["request_context"]

    # URL params
    personal_data_id = request.match_info["attribute_id"]

    # Initialise MyData DID Manager
    ada_mgr: ADAManager = ADAManager(context)

    try:

        await ada_mgr.delete_da_personal_data_in_wallet(
            personal_data_id=personal_data_id
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@docs(
    tags=["Data Agreement - MyData DID Operations"],
    summary="Mark a connection as MyData DID registry.",
    responses={
        204: {
            "description": "Connection marked as MyData DID registry."
        },
        400: {
            "description": "Bad Request"
        }
    }
)
@match_info_schema(MarkExistingConnectionAsMyDataDIDRegistryMatchInfoSchema())
async def mark_existing_connection_as_mydata_did_registry(request: web.BaseRequest):
    """
    Mark a connection as MyData DID registry.
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    connection_id = request.match_info["connection_id"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Fetch connection
        connection: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)

        # Check if connection is ready
        if not connection.is_ready:
            raise web.HTTPBadRequest(reason="Connection is not ready")

        # Mark connection as MyData DID registry
        await mydata_did_manager.mark_connection_id_as_mydata_did_registry(connection_record=connection)
    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


@docs(
    tags=["Data Agreement - MyData DID Operations"],
    summary="Fetch current connection marked as MyData DID registry",
    responses={
        400: {
            "description": "Bad Request"
        }
    }
)
@response_schema(ConnectionRecordSchema(), 200)
async def fetch_current_connection_marked_as_mydata_did_registry(request: web.BaseRequest):
    """
    Fetch current connection marked as MyData DID registry.
    """

    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Fetch current connection marked as MyData DID registry
        connection_id: str = await mydata_did_manager.fetch_current_mydata_did_registry_connection_id()

        if not connection_id:
            raise web.HTTPBadRequest(
                reason="No connection marked as MyData DID registry")

        # Fetch connection
        connection: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(connection.serialize())


@docs(
    tags=["Data Agreement - MyData DID Operations"],
    summary="Unmark current connection marked as MyData DID registry",
    responses={
        204: {
            "description": "Connection unmarked as MyData DID registry."
        },
        400: {
            "description": "Bad Request"
        }
    }
)
async def unmark_current_connection_marked_as_mydata_did_registry(request: web.BaseRequest):
    """
    Unmark current connection marked as MyData DID registry.
    """

    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Unmark connection as MyData DID registry
        unmarked = await mydata_did_manager.unmark_connection_id_as_mydata_did_registry()

        if not unmarked:
            raise web.HTTPBadRequest(
                reason="Connection is not marked as MyData DID registry")

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


@docs(
    tags=["Data Agreement - MyData DID Operations"],
    summary="Dummy MyData DID resolve route"
)
@querystring_schema(DummyDIDResolveRouteHandlerQueryStringSchema())
async def dummy_did_resolve_route_handler(request: web.BaseRequest):

    # Request context
    context = request.app["request_context"]

    # Query string parameters

    # MyData DID
    mydata_did = None
    if "did" in request.query and request.query["did"] != "":
        mydata_did = request.query["did"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:

        await mydata_did_manager.resolve_remote_mydata_did(mydata_did=mydata_did)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


@docs(
    tags=["Data Agreement - Auditor Functions"],
    summary="Mark a connection as Auditor.",
    responses={
        204: {
            "description": "Connection marked as Auditor."
        },
        400: {
            "description": "Bad Request"
        }
    }
)
@match_info_schema(MarkExistingConnectionAsAuditorMatchInfoSchema())
async def mark_existing_connection_as_auditor(request: web.BaseRequest):
    """
    Mark a connection as Auditor.
    """

    # Request context
    context = request.app["request_context"]

    # URL params
    connection_id = request.match_info["connection_id"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Fetch connection
        connection: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)

        # Check if connection is ready
        if not connection.is_ready:
            raise web.HTTPBadRequest(reason="Connection is not ready")

        # Mark connection as Auditor
        await mydata_did_manager.mark_connection_id_as_auditor(connection_record=connection)
    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


@docs(
    tags=["Data Agreement - Auditor Functions"],
    summary="Fetch current connection marked as Auditor",
    responses={
        400: {
            "description": "Bad Request"
        }
    }
)
@response_schema(ConnectionRecordSchema(), 200)
async def fetch_current_connection_marked_as_auditor(request: web.BaseRequest):
    """
    Fetch current connection marked as Auditor.
    """

    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Fetch current connection marked as Auditor
        connection_id: str = await mydata_did_manager.fetch_current_auditor_connection_id()

        if not connection_id:
            raise web.HTTPBadRequest(
                reason="No connection marked as Auditor")

        # Fetch connection
        connection: ConnectionRecord = await ConnectionRecord.retrieve_by_id(context, connection_id)

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(connection.serialize())


@docs(
    tags=["Data Agreement - Auditor Functions"],
    summary="Unmark current connection marked as Auditor",
    responses={
        204: {
            "description": "Connection unmarked as Auditor."
        },
        400: {
            "description": "Bad Request"
        }
    }
)
async def unmark_current_connection_marked_as_auditor(request: web.BaseRequest):
    """
    Unmark current connection marked as Auditor.
    """

    # Request context
    context = request.app["request_context"]

    # Initialise MyData DID Manager
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:
        # Unmark connection as Auditor
        unmarked = await mydata_did_manager.unmark_connection_id_as_auditor()

        if not unmarked:
            raise web.HTTPBadRequest(
                reason="Connection is not marked as Auditor")

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.Response(status=204)


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Query data agreement instances"
)
@querystring_schema(QueryDataAgreementInstanceQueryStringSchema())
@response_schema(DataAgreementInstanceSchema(many=True), 200)
async def query_data_agreement_instances(request: web.BaseRequest):
    """
    Request handler for querying data agreement instances.
    """

    # Context
    context = request.app["request_context"]

    # Get query string parameters
    tag_filter = {}

    # Thread ID
    if "data_agreement_id" in request.query and request.query["data_agreement_id"] != "":
        tag_filter["data_agreement_id"] = request.query["data_agreement_id"]

    # Connection ID
    if "data_agreement_template_id" in request.query and request.query["data_agreement_template_id"] != "":
        tag_filter["data_agreement_template_id"] = request.query["data_agreement_template_id"]

    # Message type
    if "method_of_use" in request.query and request.query["method_of_use"] != "":
        tag_filter["method_of_use"] = request.query["method_of_use"]

    if "data_exchange_record_id" in request.query and request.query["data_exchange_record_id"] != "":
        tag_filter["data_exchange_record_id"] = request.query["data_exchange_record_id"]

    results = []

    try:

        # Initialise MyData DID Manager
        mydata_did_manager: ADAManager = ADAManager(
            context=context
        )

        # Get the list of DIDComm transaction records
        results = await mydata_did_manager.query_data_agreement_instances(
            tag_query=tag_filter
        )

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(tags=["Data Agreement - Auditor Functions"], summary="Fetch Auditor DIDComm transaction records")
@querystring_schema(AuditorDIDCommTransactionRecordListQueryStringSchema())
@response_schema(AuditorDIDCommTransactionRecordSchema(many=True), 200)
async def auditor_didcomm_transaction_records_list(request: web.BaseRequest):
    """
    Request handler for fetching Auditor transaction records
    """

    # Context
    context = request.app["request_context"]

    # Get query string parameters
    tag_filter = {}

    # Thread ID
    if "thread_id" in request.query and request.query["thread_id"] != "":
        tag_filter["thread_id"] = request.query["thread_id"]

    # Connection ID
    if "connection_id" in request.query and request.query["connection_id"] != "":
        tag_filter["connection_id"] = request.query["connection_id"]

    results = []

    try:
        # Get the list of DIDComm transaction records
        results = await AuditorDIDCommTransactionRecord.query(context, tag_filter)

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response([result.serialize() for result in results])


@docs(tags=["Data Agreement - Auditor Functions"], summary="Fetch Auditor DIDComm transaction record by ID")
@match_info_schema(AuditorDIDCommTransactionRecordsRetrieveByIdMatchInfoSchema())
@response_schema(AuditorDIDCommTransactionRecordSchema(), 200)
async def auditor_didcomm_transaction_records_retreive_by_id(request: web.BaseRequest):
    """
    Request handler for fetching Auditor DIDComm transaction record by ID
    """

    # Context
    context = request.app["request_context"]

    # Get path parameters
    auditor_didcomm_transaction_record_id = request.match_info[
        "auditor_didcomm_transaction_record_id"]

    result = {}
    try:
        # Get the DIDComm transaction record
        auditor_didcomm_transaction_record = await AuditorDIDCommTransactionRecord.retrieve_by_id(
            context=context,
            record_id=auditor_didcomm_transaction_record_id
        )

        result = auditor_didcomm_transaction_record.serialize()

    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(
    tags=["Data Agreement - Auditor Functions"],
    summary="Remove Auditor DIDComm transaction record by ID",
    responses={
        204: {
            "description": "Auditor DIDComm transaction record removed"
        }
    }
)
@match_info_schema(AuditorDIDCommTransactionRecordsDeleteByIdMatchInfoSchema())
async def auditor_didcomm_transaction_records_delete_by_id(request: web.BaseRequest):
    """
    Request handler for removing Auditor DIDComm transaction record by ID
    """

    # Context
    context = request.app["request_context"]

    # Get path parameters
    auditor_didcomm_transaction_record_id = request.match_info[
        "auditor_didcomm_transaction_record_id"]

    try:
        # Get the DIDComm transaction record
        auditor_didcomm_transaction_record = await AuditorDIDCommTransactionRecord.retrieve_by_id(
            context=context,
            record_id=auditor_didcomm_transaction_record_id
        )

        # Delete the DIDComm transaction record
        await auditor_didcomm_transaction_record.delete_record(context)
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(None, status=204)


@docs(
    tags=["Data Agreement - Auditor Functions"],
    summary="Send data agreement verify request to the auditor"
)
@match_info_schema(AuditorSendDataAgreementVerifyRequestMatchInfoSchema())
@response_schema(AuditorDIDCommTransactionRecordSchema(), 200)
async def auditor_send_data_agreement_verify_request(request: web.BaseRequest):
    """
    Request handler to send data agreement verify request to the auditor
    """

    # Context
    context = request.app["request_context"]

    outbound_handler = request.app["outbound_message_router"]

    # Get path parameters
    data_agreement_id = request.match_info["data_agreement_id"]

    result = {}
    try:

        # Initialise MyData DID Manager
        mydata_did_manager: ADAManager = ADAManager(
            context=context
        )

        try:

            # construct the data agreement verify request
            data_agreement_verify_request = await mydata_did_manager.construct_data_agreement_verify_request(
                data_agreement_id=data_agreement_id
            )

            auditor_connection_record, err = await mydata_did_manager.fetch_auditor_connection_record()

            # create auditor DIDComm transaction record
            auditor_didcomm_transaction_record = AuditorDIDCommTransactionRecord(
                thread_id=data_agreement_verify_request._id,
                messages_list=[data_agreement_verify_request.serialize()],
                connection_id=auditor_connection_record.connection_id,
            )

            await auditor_didcomm_transaction_record.save(context)

            result = auditor_didcomm_transaction_record.serialize()

            # Send the data agreement verify request to the auditor
            await outbound_handler(
                data_agreement_verify_request, connection_id=auditor_connection_record.connection_id
            )

        except ADAManagerError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


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
                "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation"
            }
        }
    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class GenerateDataAgreementQrCodePayloadQueryStringSchema(OpenAPISchema):
    """Schema for query string parameters to generate data agreement qr code payload"""

    multi_use = fields.Bool()


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Generate Data Agreement QR code payload",
    responses={
        400: "Bad Request"
    }
)
@querystring_schema(GenerateDataAgreementQrCodePayloadQueryStringSchema())
@match_info_schema(DataAgreementQRCodeMatchInfoSchema())
@response_schema(GenerateDataAgreementQrCodePayloadResponseSchema(), 201)
async def generate_data_agreement_qr_code_payload(request: web.BaseRequest):
    # Get path parameters.
    data_agreement_id = request.match_info["data_agreement_id"]

    # Context.
    context = request.app["request_context"]

    multi_use = False if "multi_use" not in request.query else request.query["multi_use"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:

        # Call the function.

        result = await mydata_did_manager.construct_data_agreement_qr_code_payload(
            data_agreement_id=data_agreement_id,
            multi_use=multi_use
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result, status=201)


class QueryDataAgreementQrCodeMetadataRecordsMatchInfoSchema(OpenAPISchema):
    """Schema to validate path parameters for query data agreement qr code metadata records."""

    data_agreement_id = fields.Str(
        description="Data Agreement identifier", example=UUIDFour.EXAMPLE, required=False)


class QueryDataAgreementQrCodeMetadataRecordsQueryStringSchema(OpenAPISchema):
    """Schema for querying data agreement qr code metadata records"""

    qr_id = fields.Str(description="QR code identifier",
                       example=UUIDFour.EXAMPLE, required=False)


class QueryDataAgreementQRCodeMetadataRecordsResponseSchema(OpenAPISchema):
    """Schema for querying data agreement qr code metadata records response"""

    qr_id = fields.Str(description="QR code identifier",
                       example=UUIDFour.EXAMPLE, required=False)

    data_agreement_id = fields.Str(
        description="Data Agreement identifier", example=UUIDFour.EXAMPLE, required=False)

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=False)

    multi_use = fields.Bool()
    is_scanned = fields.Bool()
    data_exchange_record_id = fields.Str()


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Query Data Agreement QR code metadata records",
)
@match_info_schema(QueryDataAgreementQrCodeMetadataRecordsMatchInfoSchema())
@querystring_schema(QueryDataAgreementQrCodeMetadataRecordsQueryStringSchema())
@response_schema(QueryDataAgreementQRCodeMetadataRecordsResponseSchema(many=True))
async def query_data_agreement_qr_code_metadata_records_handler(request: web.BaseRequest):
    # Context.
    context = request.app["request_context"]

    tag_filter = {
        "data_agreement_id": request.match_info["data_agreement_id"]
    }

    # qr id
    if "qr_id" in request.query and request.query["qr_id"] != "":
        tag_filter["qr_id"] = request.query["qr_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:

        # Call the function.

        result = await mydata_did_manager.query_data_agreement_qr_metadata_records(
            query_string=tag_filter
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class RemoveDataAgreementQrCodeMetadataRecordMatchInfoSchema(OpenAPISchema):

    data_agreement_id = fields.Str(
        description="Data Agreement identifier", example=UUIDFour.EXAMPLE, required=True)

    qr_id = fields.Str(description="QR code identifier",
                       example=UUIDFour.EXAMPLE, required=True)


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Delete Data Agreement QR code record.",
    responses={
        204: {
            "description": "Success"
        },
    }
)
@match_info_schema(RemoveDataAgreementQrCodeMetadataRecordMatchInfoSchema())
async def remove_data_agreement_qr_code_metadata_record_handler(request: web.BaseRequest):

    # Context
    context = request.app["request_context"]

    # Fetch path parameters.
    data_agreement_id = request.match_info["data_agreement_id"]
    qr_id = request.match_info["qr_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(
        context=context
    )

    try:

        # Call the function.

        await mydata_did_manager.delete_data_agreement_qr_metadata_record(
            data_agreement_id=data_agreement_id,
            qr_id=qr_id
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


class Base64EncodeDataAgreementQrCodeMatchInfoSchema(OpenAPISchema):
    """Match info (URL path params) schema for base64 encode data agreement QR code payload endpoint"""

    # Data Agreement identifier.
    data_agreement_id = fields.Str(
        description="Data Agreement identifier", example=UUIDFour.EXAMPLE, required=True
    )

    # Qr code identifier
    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=True
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Base64 encode data agreement qr code payload"
)
@match_info_schema(Base64EncodeDataAgreementQrCodeMatchInfoSchema())
async def base64_encode_data_agreement_qr_code_payload_handler(request: web.BaseRequest):

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

        base64_string = await mydata_did_manager.base64_encode_data_agreement_qr_code_payload(
            data_agreement_id=data_agreement_id,
            qr_id=qr_id
        )

        result = {
            "base64_string": base64_string
        }

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class SendDataAgreementQrCodeWorkflowInitiateHandlerMatchInfoSchema(OpenAPISchema):
    """Match info (URL path params) schema for send data agreement qr code workflow initiate endpoint"""

    # Connection identifier.
    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )

    # Qr code identifier
    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=True
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Send data agreement qr code workflow initiate message to remote agent",
)
@match_info_schema(SendDataAgreementQrCodeWorkflowInitiateHandlerMatchInfoSchema())
async def send_data_agreements_qr_code_workflow_initiate_handler(request: web.BaseRequest):

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
            connection_id=connection_id,
            qr_id=qr_id
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


class GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadMatchInfoSchema(OpenAPISchema):
    """Schema to match URL path parameters in generate firebase dynamic link for data agreement qr endpoint"""

    # Data agreement identifier.
    data_agreement_id = fields.Str(
        description="Data agreement identifier", example=UUIDFour.EXAMPLE, required=True
    )

    # Qr code identifier
    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=True
    )


class GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadResponseSchema(OpenAPISchema):
    """Response schema for generate firebase dynamic link for data agreement qr endpoint"""

    # Firebase dynamic link
    firebase_dynamic_link = fields.Str(
        description="Firebase dynamic link", example="https://example.page.link/UVWXYZuvwxyz12345"
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Generate firebase dynamic link for data agreement qr code payload.",
)
@match_info_schema(GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadMatchInfoSchema())
@response_schema(GenerateFirebaseDynamicLinkForDataAgreementQRCodePayloadResponseSchema(), 200)
async def generate_firebase_dynamic_link_for_data_agreement_qr_code_payload_handler(request: web.BaseRequest):
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

        firebase_dynamic_link = await mydata_did_manager.generate_firebase_dynamic_link_for_data_agreement_qr_payload(
            data_agreement_id=data_agreement_id,
            qr_id=qr_id
        )

        result = {
            "firebase_dynamic_link": firebase_dynamic_link
        }

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class SendJSONLDDIDCommProcessedDataMessageHandlerRequestSchema(OpenAPISchema):
    data = fields.Dict()
    signature_options = fields.Dict()
    proof_chain = fields.Bool()


class SendJSONLDDIDCommProcessedDataMessageHandlerMatchInfoSchema(OpenAPISchema):

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


@docs(
    tags=["JSON-LD"],
    summary="Send JSON-LD processed-data didcomm message to the remote agent.",
    responses={
        204: {
            "description": "Success",
        },
    }
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
            proof_chain=body.get("proof_chain", False)
        )

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=204)


@web.middleware
async def authentication_middleware(request: web.BaseRequest, handler: typing.Coroutine):
    """
    Authentication middleware.

    Authenticate the request if the request headers contain Authorization header with value of ApiKey <api_key>.
    """

    # Context.
    context = request.app["request_context"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)

    try:
        # Fetch iGrant.io config from os environment.
        config: dict = await mydata_did_manager.fetch_igrantio_config_from_os_environ()
    except ADAManagerError as err:
        # iGrant.io config is not available.
        # Proceed without authentication.

        return await handler(request)

    # API Key secret
    api_key_secret = config.get("igrantio_org_api_key_secret")

    # Fetch authorization header.
    authorization_header = request.headers.get("Authorization")

    # Fetch api key from authorization header.
    api_key = authorization_header.split(
        "ApiKey ")[1] if authorization_header else None

    if not api_key:
        raise web.HTTPUnauthorized(reason="Missing Authorization header.")

    # Authenticate the request.
    try:
        jwt.decode(api_key, api_key_secret, algorithms=["HS256"])
    except jwt.exceptions.InvalidTokenError:
        try:
            jwt.decode(api_key, api_key_secret, algorithms=[
                       "HS256"], audience="dataverifier")
        except jwt.exceptions.InvalidTokenError:
            raise web.HTTPUnauthorized(reason="Invalid API Key.")

    # Override the api key in environment variable.
    os.environ["IGRANTIO_ORG_API_KEY"] = api_key

    # Call the handler.
    return await handler(request)


class V2CreateInvitationQueryStringSchema(OpenAPISchema):
    """Parameters and validators for create invitation request query string."""

    alias = fields.Str(
        description="Alias",
        required=False,
        example="Barry",
    )
    auto_accept = fields.Boolean(
        description="Auto-accept connection (default as per configuration)",
        required=False,
    )
    public = fields.Boolean(
        description="Create invitation from public DID (default false)", required=False
    )
    multi_use = fields.Boolean(
        description="Create invitation for multiple use (default false)", required=False
    )


class V2InvitationResultSchema(OpenAPISchema):
    """Result schema for a new connection invitation."""

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE
    )
    invitation = fields.Nested(ConnectionInvitationSchema())
    invitation_url = fields.Str(
        description="Invitation URL",
        example="http://192.168.56.101:8020/invite?c_i=eyJAdHlwZSI6Li4ufQ==",
    )


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


class GenerateFirebaseDynamicLinkForConnectionInvitationMatchInfoSchema(OpenAPISchema):
    """Schema for matching path parameters in generate firebase dynamic link for connection invitation handler"""

    conn_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


class GenerateFirebaseDynamicLinkForConnectionInvitationResponseSchema(OpenAPISchema):
    """Schema for response of generate firebase dynamic link for connection invitation handler"""

    # Firebase dynamic link
    firebase_dynamic_link = fields.Str(
        description="Firebase dynamic link", example="https://example.page.link/UVWXYZuvwxyz12345"
    )


@docs(
    tags=["connection"],
    summary="Generate firebase dynamic link for connection invitation",
)
@match_info_schema(GenerateFirebaseDynamicLinkForConnectionInvitationMatchInfoSchema())
@response_schema(GenerateFirebaseDynamicLinkForConnectionInvitationResponseSchema(), 200)
async def generate_firebase_dynamic_link_for_connection_invitation_handler(request: web.BaseRequest):
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
        firebase_dynamic_link = await mydata_did_manager.generate_firebase_dynamic_link_for_connection_invitation(conn_id)

    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({
        "firebase_dynamic_link": firebase_dynamic_link
    })


class SendReadAllDataAgreementTemplateMessageHandlerMatchInfoSchema(OpenAPISchema):
    """Schema for matching path parameters in send read all data agreement template message handler"""

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


@docs(
    tags=["Data Agreement - Core Functions"],
    summary="Send read all data agreement template message to remote agent.",
    responses={
        200: {
            "description": "Success",
        }
    }
)
@match_info_schema(SendReadAllDataAgreementTemplateMessageHandlerMatchInfoSchema())
async def send_read_all_data_agreement_template_message_handler(request: web.BaseRequest):
    """Send read all data agreement template message to remote agent."""

    context = request.app["request_context"]
    connection_id = request.match_info["connection_id"]

    # Initialise MyData DID Manager.
    mydata_did_manager: ADAManager = ADAManager(context=context)
    try:
        # Call the function
        await mydata_did_manager.send_read_all_data_agreement_template_message(connection_id)

    except (ConnectionManagerError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=200)


@docs(
    tags=["Data Controller"],
    summary="Send data controller details message to remote agent hosted by Data Controller",
    responses={
        200: {
            "description": "Success",
        }
    }
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


class SendExistingConnectionsMessageHandlerMatchInfoSchema(OpenAPISchema):
    """Schema for matching path parameters in send existing connections message handler"""

    conn_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


class SendExistingConnectionsMessageHandlerRequestSchema(OpenAPISchema):
    """Schema for request body of send existing connections message handler"""

    theirdid = fields.Str(
        description="Their DID",
        example="QmWbsNYhMrjHiqZDTUASHg",
        required=True
    )


@docs(
    tags=["connection"],
    summary="Send existing connections message to remote agent.",
    responses={
        200: {
            "description": "Success",
        }
    }
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
        await mydata_did_manager.send_existing_connections_message(body["theirdid"], conn_id)

    except ADAManagerError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({}, status=200)


class GetExistingConnectionMatchInfoSchema(OpenAPISchema):
    """Schema for matching path parameters in get existing connection handler"""

    conn_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


class GetExistingConnectionResponseSchema(OpenAPISchema):
    """Schema for response of get existing connection handler"""

    existing_connection_id = fields.Str()
    my_did = fields.Str()
    connection_status = fields.Str()
    connection_id = fields.Str()


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
    result = await mydata_did_manager.fetch_existing_connections_record_for_current_connection(conn_id)

    return web.json_response(result)


class ConnectionsListQueryStringSchemaV2(OpenAPISchema):
    """Parameters and validators for connections list request query string."""

    alias = fields.Str(
        description="Alias",
        required=False,
        example="Barry",
    )

    initiator = fields.Str(
        description="Connection initiator",
        required=False,
        validate=validate.OneOf(["self", "external"]),
    )

    invitation_key = fields.Str(
        description="invitation key", required=False, **INDY_RAW_PUBLIC_KEY
    )

    my_did = fields.Str(description="My DID", required=False, **INDY_DID)

    state = fields.Str(
        description="Connection state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(ConnectionRecord, m)
                for m in vars(ConnectionRecord)
                if m.startswith("STATE_")
            ]
        ),
    )

    their_did = fields.Str(description="Their DID", required=False, **INDY_DID)

    their_role = fields.Str(
        description="Their assigned connection role",
        required=False,
        example="Point of contact",
    )

    # Response fields
    include_fields = fields.Str(
        required=False,
        description="Comma separated fields to be included in the response.",
        example="connection_id,state,presentation_exchange_id",
    )

    page = fields.Int(
        required=False,
        description="Page number",
        example=1,
    )

    page_size = fields.Int(
        required=False,
        description="Page size",
        example=10,
    )


class ConnectionListSchema(OpenAPISchema):
    """Result schema for connection list."""

    results = fields.List(
        fields.Nested(ConnectionRecordSchema()),
        description="List of connection records",
    )


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
            pagination["totalCount"] / pagination["pageSize"])

        # Fields to be included in the response.
        include_fields = request.query.get("include_fields")
        include_fields = comma_separated_str_to_list(
            include_fields) if include_fields else None

        results = ADAManager.serialize_connection_record(
            records, True, include_fields)

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


async def register(app: web.Application):

    app._middlewares = frozenlist.FrozenList(
        app.middlewares[:] + [authentication_middleware])

    app.add_routes(
        [
            web.get(
                "/v1/mydata-did/didcomm/transaction-records",
                mydata_did_registry_didcomm_transaction_records_list,
                allow_head=False
            ),
            web.get(
                "/v1/mydata-did/didcomm/transaction-records/{mydata_did_registry_didcomm_transaction_record_id}",
                mydata_did_registry_didcomm_transaction_records_retreive_by_id,
                allow_head=False,
            ),
            web.delete(
                "/v1/mydata-did/didcomm/transaction-records/{mydata_did_registry_didcomm_transaction_record_id}",
                mydata_did_registry_didcomm_transaction_records_delete_by_id,
            ),
            web.post(
                "/v1/mydata-did/didcomm/create-did/{did}",
                send_create_did_message_to_mydata_did_registry
            ),
            web.post(
                "/v1/mydata-did/didcomm/read-did/{did}",
                send_read_did_message_to_mydata_did_registry
            ),
            web.post(
                "/v1/mydata-did/didcomm/delete-did/{did}",
                send_delete_did_message_to_mydata_did_registry
            ),
            web.get(
                "/v1/mydata-did/remote",
                mydata_did_remote_records_list,
                allow_head=False
            ),
            web.get(
                "/v1/mydata-did-registry/mydata-did",
                mydata_did_registry_mydata_did_list,
                allow_head=False
            ),
            web.post(
                "/v1/data-agreements/didcomm/read-data-agreement",
                send_read_data_agreement
            ),
            web.get(
                "/v1/data-agreements/didcomm/transactions",
                list_data_agreements_crud_didcomm_transactions,
                allow_head=False
            ),
            web.delete(
                "/v1/data-agreements/didcomm/transactions/{da_crud_didcomm_tx_id}",
                data_agreement_crud_didcomm_transaction_records_delete_by_id,
            ),
            web.post(
                "/v1/data-agreements",
                create_and_store_data_agreement_in_wallet_v2,
            ),
            web.post(
                "/v1/data-agreements/{data_agreement_id}/publish",
                publish_data_agreement_handler,
            ),
            web.get(
                "/v1/data-agreements",
                query_data_agreements_in_wallet,
                allow_head=False
            ),
            web.put(
                "/v1/data-agreements/{data_agreement_id}",
                update_data_agreement_in_wallet_v2,
            ),
            web.delete(
                "/v1/data-agreements/{data_agreement_id}",
                delete_data_agreement_in_wallet,
            ),
            web.get(
                "/v1/data-agreements/version-history/{data_agreement_id}",
                query_data_agreement_version_history,
                allow_head=False
            ),
            web.get(
                "/v1/data-agreements/personal-data",
                query_da_personal_data_in_wallet,
                allow_head=False
            ),
            web.put(
                "/v1/data-agreements/personal-data/{attribute_id}",
                update_da_personal_data_in_wallet,
            ),
            web.delete(
                "/v1/data-agreements/personal-data/{attribute_id}",
                delete_da_personal_data_in_wallet,
            ),
            web.post(
                "/v1/mydata-did/set-did-registry-connection/{connection_id}",
                mark_existing_connection_as_mydata_did_registry,
            ),
            web.get(
                "/v1/mydata-did/get-did-registry-connection",
                fetch_current_connection_marked_as_mydata_did_registry,
                allow_head=False
            ),
            web.delete(
                "/v1/mydata-did/unset-did-registry-connection",
                unmark_current_connection_marked_as_mydata_did_registry,
            ),
            web.get(
                "/v1/dummy-did-resolve-route",
                dummy_did_resolve_route_handler,
                allow_head=False
            ),
            web.post(
                "/v1/auditor/set-auditor-connection/{connection_id}",
                mark_existing_connection_as_auditor,
            ),
            web.get(
                "/v1/auditor/get-auditor-connection",
                fetch_current_connection_marked_as_auditor,
                allow_head=False
            ),
            web.delete(
                "/v1/auditor/unset-auditor-connection",
                unmark_current_connection_marked_as_auditor,
            ),
            web.get(
                "/v1/data-agreement-instances",
                query_data_agreement_instances,
                allow_head=False
            ),
            web.get(
                "/v1/auditor/didcomm/transaction-records",
                auditor_didcomm_transaction_records_list,
                allow_head=False
            ),
            web.get(
                "/v1/auditor/didcomm/transaction-records/{auditor_didcomm_transaction_record_id}",
                auditor_didcomm_transaction_records_retreive_by_id,
                allow_head=False,
            ),
            web.delete(
                "/v1/auditor/didcomm/transaction-records/{auditor_didcomm_transaction_record_id}",
                auditor_didcomm_transaction_records_delete_by_id,
            ),
            web.post(
                "/v1/auditor/didcomm/verify-request/{data_agreement_id}",
                auditor_send_data_agreement_verify_request
            ),
            web.get(
                "/v1/.well-known/did-configuration.json",
                wellknown_connection_handler,
                allow_head=False
            ),
            web.post(
                "/v1/data-agreements/{data_agreement_id}/qr",
                generate_data_agreement_qr_code_payload,
            ),
            web.get(
                "/v1/data-agreements/{data_agreement_id}/qr/{qr_id}/base64",
                base64_encode_data_agreement_qr_code_payload_handler,
                allow_head=False
            ),
            web.post(
                "/v1/data-agreements/{data_agreement_id}/qr/{qr_id}/firebase",
                generate_firebase_dynamic_link_for_data_agreement_qr_code_payload_handler,
            ),
            web.get(
                "/v1/data-agreements/{data_agreement_id}/qr",
                query_data_agreement_qr_code_metadata_records_handler,
                allow_head=False
            ),
            web.delete(
                "/v1/data-agreements/{data_agreement_id}/qr/{qr_id}",
                remove_data_agreement_qr_code_metadata_record_handler,
            ),
            web.post(
                "/v1/data-agreements/qr/{qr_id}/workflow-initiate/connections/{connection_id}",
                send_data_agreements_qr_code_workflow_initiate_handler,
            ),
            web.post(
                "/v1/json-ld/didcomm/processed-data/connections/{connection_id}",
                send_json_ld_didcomm_processed_data_message_handler,
            ),
            web.post(
                "/v2/connections/create-invitation",
                v2_connections_create_invitation
            ),
            web.post(
                "/v1/connections/{conn_id}/invitation/firebase",
                generate_firebase_dynamic_link_for_connection_invitation_handler
            ),
            web.post(
                "/v1/data-agreements/didcomm/read-all-template/connections/{connection_id}",
                send_read_all_data_agreement_template_message_handler
            ),
            web.post(
                "/v1/data-controller/didcomm/details/connections/{connection_id}",
                send_data_controller_details_message_handler
            ),
            web.post(
                "/v1/connections/{conn_id}/existing",
                send_existing_connections_message_handler
            ),
            web.get(
                "/v1/connections/{conn_id}/existing",
                get_existing_connections_handler,
                allow_head=False
            ),
            web.get(
                "/v2/connections",
                connections_list_v2,
                allow_head=False
            )
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "Data Agreement - MyData DID Operations",
            "description": "MyData DID Protocol 1.0 (ADA RFC 0001)",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/didcomm-protocol-spec.md"},
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "Data Agreement - MyData DID Registry Admin Functions",
            "description": "MyData DID registry administrative functions",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/didcomm-protocol-spec.md"},
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "Data Agreement - Core Functions",
            "description": "Data Agreement Protocol 1.0 (ADA RFC 0002)",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/didcomm-protocol-spec.md"},
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "Data Agreement - Auditor Functions",
            "description": "Data Agreement Proofs Protocol 1.0 (ADA RFC 0004)",
            "externalDocs": {"description": "Specification", "url": "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/main/docs/didcomm-protocol-spec.md"},
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "JSON-LD",
            "description": "JSON-LD functions",
        }
    )

    app._state["swagger_dict"]["tags"].append(
        {
            "name": "Data Controller",
            "description": "Data Controller functions",
        }
    )
