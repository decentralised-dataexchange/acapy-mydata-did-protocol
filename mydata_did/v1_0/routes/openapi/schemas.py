from aries_cloudagent.connections.models.connection_record import (
    ConnectionRecord,
    ConnectionRecordSchema,
)
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.valid import (
    INDY_DID,
    INDY_RAW_PUBLIC_KEY,
    UUID4,
    UUIDFour,
)
from aries_cloudagent.protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitationSchema,
)
from dexa_sdk.agreements.da.v1_0.records.da_instance_permission_record import (
    DAInstancePermissionRecord,
)
from dexa_sdk.agreements.da.v1_0.records.third_party_data_sharing_preferences_record import (
    ThirdParyDAPreferenceRecord,
)
from marshmallow import fields, validate, validates
from marshmallow.exceptions import ValidationError
from mydata_did.v1_0.models.diddoc_model import MyDataDIDDocSchema
from mydata_did.v1_0.models.exchange_records.data_agreement_didcomm_transaction_record import (
    DataAgreementCRUDDIDCommTransaction,
)
from mydata_did.v1_0.models.exchange_records.data_agreement_record import (
    DataAgreementV1Record,
)
from mydata_did.v1_0.utils.regex import MYDATA_DID


class ReadDataAgreementRequestSchema(OpenAPISchema):
    data_agreement_id = fields.Str(
        description="Data agreement identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )
    connection_id = fields.UUID(
        description="Connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
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


class DataAgreementCRUDDIDCommTransactionRecordDeleteByIdMatchInfoSchema(OpenAPISchema):
    """Delete a transaction record by its identifier."""

    da_crud_didcomm_tx_id = fields.Str(
        description="Data agreement CRUD didcomm transaction identifier",
        required=True,
        **UUID4,
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
        fields.Nested(CreateOrUpdateDataAgreementPersonalDataRestrictionSchema),
        description="List of restrictions",
        required=False,
    )


class DPIAOpenAPISchema(OpenAPISchema):
    dpia_date = fields.Str(data_key="dpiaDate")
    dpia_summary_url = fields.Str(data_key="dpiaSummaryUrl")


class PersonalDataRestrictionOpenAPISchema(OpenAPISchema):
    schema_id = fields.Str(data_key="schemaId")
    cred_def_id = fields.Str(data_key="credDefId")


class PersonalDataOpenAPISchema(OpenAPISchema):
    attribute_id = fields.Str(data_key="attributeId")
    attribute_name = fields.Str(data_key="attributeName")
    attribute_sensitive = fields.Bool(data_key="attributeSensitive")
    attribute_category = fields.Str(data_key="attributeCategory")
    attribute_description = fields.Str(data_key="attributeDescription")
    restrictions = fields.List(
        fields.Nested(PersonalDataRestrictionOpenAPISchema), data_key="restrictions"
    )


class DataPolicyOpenAPISchema(OpenAPISchema):
    policy_url = fields.Str(data_key="policyUrl")
    jurisdiction = fields.Str(data_key="jurisdiction")
    industry_sector = fields.Str(data_key="industrySector")
    data_retention_period = fields.Int(data_key="dataRetentionPeriod")
    geographic_restriction = fields.Str(data_key="geographicRestriction")
    storage_location = fields.Str(data_key="storageLocation")
    third_party_data_sharing = fields.Bool(data_key="thirdPartyDataSharing")


class CreateOrUpdateDataAgreementInWalletRequestSchema(OpenAPISchema):
    language = fields.Str(data_key="language")
    data_controller_name = fields.Str(data_key="dataControllerName")
    data_controller_url = fields.Str(data_key="dataControllerUrl")
    data_policy = fields.Nested(DataPolicyOpenAPISchema, data_key="dataPolicy")
    purpose = fields.Str(data_key="purpose")
    purpose_descripton = fields.Str(data_key="purposeDescription")
    lawful_basis = fields.Str(data_key="lawfulBasis")
    method_of_use = fields.Str(data_key="methodOfUse")
    personal_data = fields.List(
        fields.Nested(PersonalDataOpenAPISchema), data_key="personalData"
    )
    dpia = fields.Nested(DPIAOpenAPISchema, data_key="dpia")


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
            raise ValidationError("Attribute name must be at least 3 characters long")

    # Attribute name
    attribute_name = fields.Str(
        example="Name", description="Name of the attribute", required=True
    )

    # Attribute description
    attribute_description = fields.Str(
        required=True,
        description="The description of the attribute.",
        example="Name of the customer",
    )

    restrictions = fields.List(
        fields.Nested(CreateOrUpdateDataAgreementPersonalDataRestrictionSchema),
        description="List of restrictions",
        required=False,
    )


class CreateOrUpdateDataAgreementInWalletRequestSchemaV2(
    CreateOrUpdateDataAgreementInWalletRequestSchema
):
    # Data agreement personal data (attributes)
    personal_data = fields.List(
        fields.Nested(CreateOrUpdateDataAgreementPersonalDataWithoutAttributeIdSchema),
        required=True,
    )


class DataAgreementV1RecordResponseSchema(OpenAPISchema):
    """
    Schema for data agreement v1 record response
    """

    template_id = fields.Str()
    state = fields.Str()
    method_of_use = fields.Str()
    data_agreement = fields.Dict()
    schema_id = fields.Str()
    cred_def_id = fields.Str()
    presentation_request = fields.Dict()
    publish_flag = fields.Str()
    delete_flag = fields.Str()
    existing_schema_flag = fields.Str()
    latest_version_flag = fields.Str()


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

    template_id = fields.Str(
        description="Template identifier",
        required=False,
    )

    template_version = fields.Str(
        description="Template version",
    )

    delete_flag = fields.Bool(
        description="Query deleted templates",
        required=False,
    )

    publish_flag = fields.Bool(
        description="Query published templates",
        required=False,
    )

    third_party_data_sharing = fields.Bool(
        description="Third party data sharing",
        required=False,
    )

    latest_version_flag = fields.Bool(
        description="Latest version of the template",
        required=False,
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

    template_id = fields.Str(description="Template identifier", required=True)


class DeleteDataAgreementMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the delete data agreement endpoint
    """

    template_id = fields.Str(description="Template identifier", required=True)


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
            raise ValidationError("Attribute name must be at least 3 characters long")

    # Attribute name
    attribute_name = fields.Str(
        example="Name", description="Name of the attribute", required=True
    )

    # Attribute sensitive
    attribute_sensitive = fields.Bool(
        example=True, description="Sensitivity of the attribute", required=False
    )

    # Attribute category
    attribute_category = fields.Str(
        example="Personal", description="Category of the attribute", required=False
    )

    @validates("attribute_description")
    def validate_attribute_description(self, attribute_description):
        """
        Validate attribute description
        """
        if len(attribute_description) < 3:
            raise ValidationError(
                "Attribute description must be at least 3 characters long"
            )

        if len(attribute_description) > 1000:
            raise ValidationError(
                "Attribute description must be at most 1000 characters long"
            )

    # Attribute description
    attribute_description = fields.Str(
        example="Name of the user",
        description="Description of the attribute",
        required=False,
    )


class QueryDAPersonalDataInWalletQueryStringSchema(OpenAPISchema):
    """
    Schema for the query personal data in wallet query string
    """

    attribute_sensitive = fields.Bool(
        description="Sensitivity of the attribute", required=False
    )

    attribute_category = fields.Str(
        description="Category of the attribute", required=False
    )


class ListDAPersonalDataCategoryFromWalletResponseSchema(OpenAPISchema):
    """
    Schema for the list personal data category from wallet response
    """

    # List of categories
    categories = fields.List(
        fields.Str(description="Category", example="Personal"),
        description="List of categories",
        required=True,
    )


class MarkExistingConnectionAsAuditorMatchInfoSchema(OpenAPISchema):
    """
    Schema for the mark existing connection as auditor match info
    """

    connection_id = fields.Str(
        example=UUIDFour.EXAMPLE, description="Connection identifier", required=True
    )


class QueryDataAgreementInstanceQueryStringSchema(OpenAPISchema):
    """
    Query data agreement instances
    """

    instance_id = fields.Str(required=False)
    template_id = fields.Str(required=False)
    template_version = fields.Str(required=False)
    method_of_use = fields.Str(
        required=False,
        validate=validate.OneOf(
            [
                "data-source",
                "data-using-service",
            ]
        ),
    )
    third_party_data_sharing = fields.Bool(required=False)
    data_ex_id = fields.Str(required=False)
    data_subject_did = fields.Str(required=False)
    page = fields.Int(required=False)
    page_size = fields.Int(required=False)


class AuditorSendDataAgreementVerifyRequestMatchInfoSchema(OpenAPISchema):
    """
    Schema to send data agreement verify request to the auditor
    """

    data_agreement_id = fields.Str(
        description="Data agreement identifier",
        required=True,
        example=UUIDFour.EXAMPLE,
    )


class DataAgreementQRCodeMatchInfoSchema(OpenAPISchema):
    """
    Schema for data agreement QR code match info
    """

    template_id = fields.Str(required=True)


class DataAgreementQRCodeInvitationSchema(OpenAPISchema):
    """Schema for connection invitation details inside in data agreement qr code payload."""

    service_endpoint = fields.Str(
        description="Service endpoint", example="http://localhost:8080/"
    )
    recipient_key = fields.Str(description="Recipient key", **INDY_RAW_PUBLIC_KEY)


class GenerateDataAgreementQrCodePayloadResponseSchema(OpenAPISchema):
    """
    Schema for Data Agreement QR code payload
    """

    qr_id = fields.Str(description="QR code ID", **UUID4)
    connection_id = fields.Str(description="Connection ID", **UUID4)
    invitation = fields.Nested(
        DataAgreementQRCodeInvitationSchema(),
        description="Connection invitation information",
    )


class SendReadDIDMessageMatchInfoSchema(OpenAPISchema):
    """
    Send a read-did message to the MyData DID registry service.
    """

    did = fields.Str(description="did:mydata identifier", required=True, **MYDATA_DID)


class MyDataDIDRemoteRecordsQueryStringSchema(OpenAPISchema):
    """
    Query string schema for listing MyData DID remote records.
    """

    # Sovrin verkey
    sov_verkey = fields.Str(
        description="Sovrin verkey", required=False, **INDY_RAW_PUBLIC_KEY
    )

    # DID
    did = fields.Str(**MYDATA_DID, description="MyData decentralised identifier")

    # Status
    status = fields.Str(
        description="MyData DID remote status",
        required=False,
        validate=validate.OneOf(["active", "revoked"]),
    )


class MyDataDIDRemoteRecordResponseSchema(OpenAPISchema):
    """
    Response schema for MyData DID remote record.
    """

    did_doc = fields.Nested(
        MyDataDIDDocSchema,
        description="MyData DID document",
    )

    did = fields.Str(**MYDATA_DID, description="MyData decentralised identifier")

    sov_verkey = fields.Str(
        description="Sovrin verkey", required=False, **INDY_RAW_PUBLIC_KEY
    )

    status = fields.Str(
        description="MyData DID remote status",
        required=False,
        validate=validate.OneOf(["active", "revoked"]),
    )


class CreateOrUpdateDataAgreementInWalletQueryStringSchema(OpenAPISchema):
    """Query string schema for create data agreement handler"""

    publish_flag = fields.Boolean(
        description="Publish the agreement", required=False, example=False
    )

    existing_schema_id = fields.Str(
        description="Existing schema identifier",
        required=False,
        example="issuer_did:1:schema:1",
    )


class UpdateDataAgreementTemplateOpenAPISchema(OpenAPISchema):
    publish_flag = fields.Boolean(required=False)
    existing_schema_id = fields.Str(required=False)


class PublishDataAgreementMatchInfoSchema(OpenAPISchema):
    """
    Schema to match info for the publish data agreement endpoint
    """

    template_id = fields.Str()


class QueryDaPersonalDataInWalletQueryStringSchema(OpenAPISchema):
    template_id = fields.Str(required=False)
    page = fields.Int(required=False)
    page_size = fields.Int(required=False)
    method_of_use = fields.Str(
        required=False,
        validate=validate.OneOf(
            [
                "data-source",
                "data-using-service",
            ]
        ),
    )
    third_party_data_sharing = fields.Bool(required=False)


class UpdateDaPersonalDataInWalletMatchInfoSchema(OpenAPISchema):

    attribute_id = fields.Str(
        required=True, description="Personal data identifier", example=UUIDFour.EXAMPLE
    )


class UpdateDaPersonalDataInWalletRequestSchema(OpenAPISchema):
    attribute_description = fields.Str(
        description="Attribute description", example="Age of the patient", required=True
    )


class UpdateDaPersonalDataInWalletResponseSchema(OpenAPISchema):

    attribute_id = fields.Str(description="Attribute ID", example=UUIDFour.EXAMPLE)
    attribute_name = fields.Str(description="Attribute name", example="Name")
    attribute_description = fields.Str(
        description="Attribute description", example="Name of the patient"
    )
    data_agreement_template_id = fields.Str(
        description="Data Agreement Template ID", example=UUIDFour.EXAMPLE
    )
    data_agreement_template_version = fields.Integer(
        description="Data Agreement Template version", example=1
    )
    created_at = fields.Integer(
        description="Created at (Epoch time in seconds)", example=1578012800
    )
    updated_at = fields.Integer(
        description="Updated at (Epoch time in seconds)", example=1578012800
    )


class DeleteDaPersonalDataInWalletMatchInfoSchema(OpenAPISchema):

    attribute_id = fields.Str(
        required=True, description="Personal data identifier", example=UUIDFour.EXAMPLE
    )


class QueryDataAgreementQrCodeMetadataRecordsMatchInfoSchema(OpenAPISchema):
    """Schema to validate path parameters for query data agreement qr code metadata records."""

    template_id = fields.Str(
        description="Template identifier",
        example=UUIDFour.EXAMPLE,
        required=False,
    )


class QueryDataAgreementQrCodeMetadataRecordsQueryStringSchema(OpenAPISchema):
    """Schema for querying data agreement qr code metadata records"""

    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=False
    )


class QueryDataAgreementQRCodeMetadataRecordsResponseSchema(OpenAPISchema):
    """Schema for querying data agreement qr code metadata records response"""

    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=False
    )

    data_agreement_id = fields.Str(
        description="Data Agreement identifier",
        example=UUIDFour.EXAMPLE,
        required=False,
    )

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=False
    )

    multi_use = fields.Bool()
    is_scanned = fields.Bool()
    data_exchange_record_id = fields.Str()


class RemoveDataAgreementQrCodeMetadataRecordMatchInfoSchema(OpenAPISchema):
    template_id = fields.Str()
    qr_id = fields.Str()


class Base64EncodeDataAgreementQrCodeMatchInfoSchema(OpenAPISchema):
    """Match info (URL path params) schema for base64 encode
    data agreement QR code payload endpoint"""

    # Data Agreement identifier.
    data_agreement_id = fields.Str(
        description="Data Agreement identifier", example=UUIDFour.EXAMPLE, required=True
    )

    # Qr code identifier
    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=True
    )


class SendDataAgreementQrCodeWorkflowInitiateHandlerMatchInfoSchema(OpenAPISchema):
    """Match info (URL path params) schema for send
    data agreement qr code workflow initiate endpoint"""

    # Connection identifier.
    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )

    # Qr code identifier
    qr_id = fields.Str(
        description="QR code identifier", example=UUIDFour.EXAMPLE, required=True
    )


class SendReadAllDataAgreementTemplateMessageHandlerMatchInfoSchema(OpenAPISchema):
    """Schema for matching path parameters in send read all
    data agreement template message handler"""

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


class GenerateDataAgreementQrCodePayloadQueryStringSchema(OpenAPISchema):
    """Schema for query string parameters to generate data agreement qr code payload"""

    multi_use = fields.Bool()


class SendJSONLDDIDCommProcessedDataMessageHandlerRequestSchema(OpenAPISchema):
    data = fields.Dict()
    signature_options = fields.Dict()
    proof_chain = fields.Bool()


class SendJSONLDDIDCommProcessedDataMessageHandlerMatchInfoSchema(OpenAPISchema):

    connection_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


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


class GenerateFirebaseDynamicLinkForConnectionInvitationMatchInfoSchema(OpenAPISchema):
    """Schema for matching path parameters in generate firebase
    dynamic link for connection invitation handler"""

    conn_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


class GenerateFirebaseDynamicLinkForConnectionInvitationResponseSchema(OpenAPISchema):
    """Schema for response of generate firebase dynamic link for connection invitation handler"""

    # Firebase dynamic link
    firebase_dynamic_link = fields.Str(
        description="Firebase dynamic link",
        example="https://example.page.link/UVWXYZuvwxyz12345",
    )


class SendExistingConnectionsMessageHandlerMatchInfoSchema(OpenAPISchema):
    """Schema for matching path parameters in send existing connections message handler"""

    conn_id = fields.Str(
        description="Connection identifier", example=UUIDFour.EXAMPLE, required=True
    )


class SendExistingConnectionsMessageHandlerRequestSchema(OpenAPISchema):
    """Schema for request body of send existing connections message handler"""

    theirdid = fields.Str(
        description="Their DID", example="QmWbsNYhMrjHiqZDTUASHg", required=True
    )


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

    # Page
    page = fields.Int(
        required=False,
        description="Page number",
        example=1,
    )

    # Page size
    page_size = fields.Int(
        required=False,
        description="Page size",
        example=10,
    )

    # Org flag
    org_flag = fields.Bool(required=False)

    # Marketplace flag
    marketplace_flag = fields.Bool(required=False)


class ConnectionListSchema(OpenAPISchema):
    """Result schema for connection list."""

    results = fields.List(
        fields.Nested(ConnectionRecordSchema()),
        description="List of connection records",
    )


class UpdateControllerDetailsRequestSchema(OpenAPISchema):
    """Update controller details request schema"""

    organisation_did = fields.Str(required=False)
    organisation_name = fields.Str(required=False)
    cover_image_url = fields.Str(required=False)
    logo_image_url = fields.Str(required=False)
    location = fields.Str(required=False)
    organisation_type = fields.Str(required=False)
    description = fields.Str(required=False)
    policy_url = fields.Str(required=False)
    eula_url = fields.Str(required=False)


class ConfigureCustomerIdentificationDAMatchInfoSchema(OpenAPISchema):
    """Configure customer identification DA match info schema"""

    template_id = fields.Str()


class SetDAPermissionMatchInfoSchema(OpenAPISchema):
    """Set DA permission match info schema"""

    instance_id = fields.Str()


class SetDAPermissionQueryStringSchema(OpenAPISchema):
    """Set DA permission query string schema"""

    state = fields.Str(
        description="Permission state",
        required=True,
        validate=validate.OneOf(
            [
                getattr(DAInstancePermissionRecord, m)
                for m in vars(DAInstancePermissionRecord)
                if m.startswith("STATE_")
            ]
        ),
    )


class V2ReceiveConnectionInvitationRequestSchema(OpenAPISchema):
    """V2 receive connection invitation request schema"""

    connection_url = fields.Str()


class ListDUSForThirdpartySharingDAMatchInfoSchema(OpenAPISchema):
    """List DUS for third party sharing DA match info schema."""

    instance_id = fields.Str()


class SendFetchPreferenceMessageQueryStringSchema(OpenAPISchema):
    """Send fetch preference message query string schema"""

    connection_id = fields.Str()


class SendUpdatePreferencesMatchInfoSchema(OpenAPISchema):
    """Send update preferences match info schema"""

    dda_instance_id = fields.Str()
    da_instance_id = fields.Str()


class SendUpdatePreferencesQueryStringSchema(OpenAPISchema):
    """Send update preference query string schema"""

    state = fields.Str(
        description="Permission state",
        required=True,
        validate=validate.OneOf(
            [
                getattr(ThirdParyDAPreferenceRecord, m)
                for m in vars(ThirdParyDAPreferenceRecord)
                if m.startswith("STATE_")
            ]
        ),
    )
