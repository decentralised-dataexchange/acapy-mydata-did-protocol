import datetime
from typing import List

import validators
from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import EXCLUDE, fields, pre_load, validate, validates
from marshmallow.exceptions import ValidationError
from mydata_did.v1_0.utils.regex import MYDATA_DID

DATA_AGREEMENT_V1_SCHEMA_CONTEXT = "https://raw.githubusercontent.com/decentralised-dataexchange/automated-data-agreements/main/interface-specs/data-agreement-schema/v1/data-agreement-schema-context.jsonld"


class DataAgreementDataPolicy(BaseModel):
    """
    Data policy model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementDataPolicySchema"

    def __init__(
        self,
        *,
        data_retention_period: int,
        policy_url: str,
        jurisdiction: str,
        industry_scope: str,
        geographic_restriction: str,
        storage_location: str,
        third_party_data_sharing: bool,
        **kwargs,
    ):
        """
        Initialize data policy model
        """

        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.data_retention_period = data_retention_period
        self.policy_url = policy_url
        self.jurisdiction = jurisdiction
        self.industry_scope = industry_scope
        self.geographic_restriction = geographic_restriction
        self.storage_location = storage_location
        self.third_party_data_sharing = third_party_data_sharing


class DataAgreementDataPolicySchema(BaseModelSchema):
    """
    Data policy schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementDataPolicy

        # Unknown fields are excluded
        unknown = EXCLUDE

    @validates("data_retention_period")
    def validate_data_retention_period(self, data_retention_period):
        """
        Validate data retention period
        """
        if data_retention_period < 1:
            raise ValidationError(
                "Data retention period must be greater than or equal to 1"
            )

    # Data retention period
    data_retention_period = fields.Int(
        data_key="data_retention_period",
        example=365,
        description="Data retention period in days",
        required=True,
    )

    @validates("policy_url")
    def validate_policy_url(self, policy_url):
        """
        Validate policy url
        """
        if not validators.url(policy_url):
            raise ValidationError("Policy URL is not valid")

    # Policy URL
    policy_url = fields.Str(
        data_key="policy_URL",
        example="https://clarifyhealth.com/privacy-policy/",
        description="Policy URL",
        required=True,
    )

    # Jurisdiction
    jurisdiction = fields.Str(
        data_key="jurisdiction",
        example="Sweden",
        description="Jurisdiction",
        required=True,
    )

    # Industry scope
    industry_scope = fields.Str(
        data_key="industry_sector",
        example="Healthcare",
        description="Industry scope",
        required=False,
    )

    # Geographic restriction
    geographic_restriction = fields.Str(
        data_key="geographic_restriction",
        example="Europe",
        description="Geographic restriction",
        required=True,
    )

    # Storage location
    storage_location = fields.Str(
        data_key="storage_location",
        example="Europe",
        description="Storage location",
        required=True,
    )

    third_party_data_sharing = fields.Bool(
        data_key="third_party_data_sharing",
        example=False,
        description="Third party data sharing",
        required=True,
    )


class DataAgreementDPIA(BaseModel):
    """
    DPIA model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementDPIASchema"

    def __init__(self, *, dpia_date: str, dpia_summary_url: str, **kwargs):
        """
        Initialize DPIA model
        """
        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.dpia_date = dpia_date
        self.dpia_summary_url = dpia_summary_url


class DataAgreementDPIASchema(BaseModelSchema):
    """
    DPIA schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementDPIA

        # Unknown fields are excluded
        unknown = EXCLUDE

    # DPIA date
    dpia_date = fields.Str(
        data_key="dpia_date",
        example=str(
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        ),
        description="DPIA conducted date time in ISO 8601 UTC date time format",
        required=False,
    )

    # DPIA summary URL
    dpia_summary_url = fields.Str(
        data_key="dpia_summary_url",
        example="https://org.com/dpia_results.html",
        description="DPIA summary URL",
        required=False,
    )


class DataAgreementPersonalDataRestriction(BaseModel):
    """
    Personal data restriction model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementPersonalDataRestrictionSchema"

    def __init__(self, *, schema_id: str = None, cred_def_id: str = None, **kwargs):
        """
        Initialise personal data restriction model.
        """

        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.schema_id = schema_id
        self.cred_def_id = cred_def_id


class DataAgreementPersonalDataRestrictionSchema(BaseModelSchema):
    """
    Personal data restriction schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementPersonalDataRestriction

    schema_id = fields.Str(
        description="Schema identifier",
        example="WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0",
        required=False,
    )

    cred_def_id = fields.Str(
        description="Credential definition identifier",
        example="WgWxqztrNooG92RXvxSTWv:3:CL:20:tag",
        required=False,
    )

    @pre_load
    def unwrap_envelope(self, data: dict, **kwargs):

        if len(data.values()) < 1:
            raise ValidationError(
                "Personal data restriction must contain at least one attribute."
            )

        return data


class DataAgreementPersonalData(BaseModel):
    """
    Personal data model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementPersonalDataSchema"

    def __init__(
        self,
        *,
        attribute_id: str = None,
        attribute_name: str = None,
        attribute_sensitive: bool = None,
        attribute_category: str = None,
        attribute_description: str = None,
        restrictions: List[DataAgreementPersonalDataRestriction] = None,
        **kwargs,
    ):
        """
        Initialize personal data model
        """

        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.attribute_id = attribute_id
        self.attribute_name = attribute_name
        self.attribute_sensitive = attribute_sensitive
        self.attribute_category = attribute_category
        self.attribute_description = attribute_description
        self.restrictions = restrictions


class DataAgreementPersonalDataSchema(BaseModelSchema):
    """
    Personal data schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementPersonalData

    # Attribute identifier
    attribute_id = fields.Str(
        example=UUIDFour.EXAMPLE,
        description="Attribute identifier",
        required=False,
    )

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

    # Attribute description
    attribute_description = fields.Str(
        required=True,
        description="The description of the attribute.",
        example="Name of the customer",
    )

    restrictions = fields.List(
        fields.Nested(DataAgreementPersonalDataRestrictionSchema), required=False
    )


class DataAgreementEvent(BaseModel):
    """
    Data agreement event model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementEventSchema"

        # Unknown fields are excluded
        unknown = EXCLUDE

    def __init__(
        self,
        *,
        event_id: str = None,
        time_stamp: str = None,
        principle_did: str = None,
        state: str = None,
        **kwargs,
    ):
        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.event_id = event_id
        self.time_stamp = time_stamp
        self.principle_did = principle_did
        self.state = state


class DataAgreementEventSchema(BaseModelSchema):
    """
    Data agreement event schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementEvent

    event_id = fields.Str(
        data_key="id",
        example="did:mydata:z6MkfiSdYhnLnS6jfwSf2yS2CiwwjZGmFUFL5QbyL2Xu8z2E",
        description="Data agreement event identifier",
    )

    # Time stamp
    time_stamp = fields.Str(
        data_key="time_stamp",
        example=str(
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        ),
        description="Data agreement event timestamp in ISO 8601 UTC date time format",
        dump_only=True,
    )

    # Principle DID
    principle_did = fields.Str(
        data_key="data_subject_did",
        description="MyData decentralised identifier",
        dump_only=True,
        **MYDATA_DID,
    )

    # State
    state = fields.Str(
        description="State of the event", example="capture", dump_only=True
    )


class DataAgreementV1(BaseModel):
    """
    Data agreement model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementV1Schema"

    def __init__(
        self,
        *,
        context: str = None,
        data_agreement_template_id: str = None,
        data_agreement_template_version: int = None,
        pii_controller_name: str = None,
        pii_controller_url: str = None,
        usage_purpose: str = None,
        usage_purpose_description: str = None,
        legal_basis: str = None,
        method_of_use: str = None,
        data_policy: DataAgreementDataPolicy = None,
        personal_data: List[DataAgreementPersonalData] = None,
        dpia: DataAgreementDPIA = None,
        **kwargs,
    ):
        """
        Initialize data agreement model
        """

        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.context = context
        self.data_agreement_template_id = data_agreement_template_id
        self.data_agreement_template_version = data_agreement_template_version
        self.pii_controller_name = pii_controller_name
        self.pii_controller_url = pii_controller_url
        self.usage_purpose = usage_purpose
        self.usage_purpose_description = usage_purpose_description
        self.legal_basis = legal_basis
        self.method_of_use = method_of_use
        self.data_policy = data_policy
        self.personal_data = personal_data
        self.dpia = dpia


class DataAgreementV1Schema(BaseModelSchema):
    """
    Data agreement schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementV1

        # Unknown fields are excluded
        unknown = EXCLUDE

    # Data agreement schema context i.e. which schema is used
    context = fields.Str(
        data_key="@context",
        example="https://raw.githubusercontent.com/decentralised-dataexchange/automated-data-agreements/main/interface-specs/data-agreement-schema/v1/data-agreement-schema-context.jsonld",
        description="Context of the schema",
        required=True,
    )

    # TODO: "data_agreement_id" and "data_agreement_version" are only
    # TODO: ... generated when the data agreement is presented to the end user
    # TODO: ... therefore they will only be part of DataAgreement "instance"
    # # Data agreement instance identifier
    # # i.e. identifier of the "capture" data agreement instance
    # data_agreement_id = fields.Str(
    #     data_key="id",
    #     example=UUIDFour.EXAMPLE,
    #     description="Data agreement identifier",
    #     required=False,
    # )

    # # Data agreement instance version
    # # i.e. version of the "capture" data agreement instance
    # data_agreement_version = fields.Str(
    #     data_key="version",
    #     example="v1.0",
    #     description="Data agreement version",
    #     dump_only=True,
    # )

    # Data agreement template identifier
    # i.e. identifier of the "prepared" data agreement template
    data_agreement_template_id = fields.Str(
        data_key="template_id",
        example=UUIDFour.EXAMPLE,
        description="Data agreement template identifier",
    )

    # Data agreement template version
    # i.e. version of the "prepared" data agreement template
    data_agreement_template_version = fields.Int(
        data_key="template_version",
        example=1,
        description="Data agreement template version",
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
        required=True,
    )

    @validates("pii_controller_url")
    def validate_pii_controller_url(self, value):
        """
        Validate data agreement schema pii controller url
        """
        if not validators.url(value):
            raise ValidationError(f"Provided PII controller URL is not valid.")

    # Data agreement data controller URL
    pii_controller_url = fields.Str(
        data_key="data_controller_url",
        example="https://www.happyshopping.com",
        description="PII controller URL",
    )

    @validates("usage_purpose")
    def validate_usage_purpose(self, value):
        """
        Validate data agreement schema usage purpose
        """
        if len(value) < 3:
            raise ValidationError(f"Usage purpose must be at least 3 characters long.")
        if len(value) > 100:
            raise ValidationError(f"Usage purpose must be at most 100 characters long.")

    # Data agreement usage purpose
    usage_purpose = fields.Str(
        data_key="purpose",
        example="Customized shopping experience",
        description="Usage purpose title",
        required=True,
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
        required=True,
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
        ),
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
        ),
    )

    # Data agreement data policy
    data_policy = fields.Nested(DataAgreementDataPolicySchema, required=True)

    # Data agreement personal data (attributes)
    personal_data = fields.List(
        fields.Nested(DataAgreementPersonalDataSchema),
        required=True,
        validate=validate.Length(min=1),
    )

    # Data agreement DPIA metadata
    dpia = fields.Nested(DataAgreementDPIASchema, required=False)

    # TODO: "event" list will be populated during the capture phase of DA lifecycle
    # event = fields.List(fields.Nested(
    #     DataAgreementEventSchema), dump_only=True)
