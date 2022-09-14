import datetime
import typing

from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import EXCLUDE, fields, validate
from mydata_did.v1_0.models.data_agreement_model import (
    DATA_AGREEMENT_V1_SCHEMA_CONTEXT,
    DataAgreementDataPolicy,
    DataAgreementDataPolicySchema,
    DataAgreementDPIA,
    DataAgreementDPIASchema,
    DataAgreementPersonalData,
    DataAgreementPersonalDataSchema,
)
from mydata_did.v1_0.utils.jsonld import ED25519_2018_CONTEXT_URL
from mydata_did.v1_0.utils.regex import MYDATA_DID
from mydata_did.v1_0.utils.util import current_datetime_in_iso8601


class DataAgreementProof(BaseModel):
    """
    Data agreement proof model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementProofSchema"

        # Unknown fields are excluded
        unknown = EXCLUDE

    def __init__(
        self,
        *,
        proof_id: str = None,
        proof_type: str = None,
        created: str = None,
        verification_method: str = None,
        proof_purpose: str = None,
        proof_value: str = None,
        **kwargs
    ):
        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.proof_id = proof_id
        self.proof_type = proof_type
        self.created = created
        self.verification_method = verification_method
        self.proof_purpose = proof_purpose
        self.proof_value = proof_value


class DataAgreementProofSchema(BaseModelSchema):
    """
    Data agreement proof schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementProof

    # Proof identifier
    proof_id = fields.Str(
        data_key="id",
        example="did:mydata:123456789abcdefghi#1",
        description="Proof identifier",
        required=False,
    )

    # Proof type
    proof_type = fields.Str(
        data_key="type",
        example="Ed25519Signature2018",
        description="Proof type",
        required=False,
    )

    # Created
    created = fields.Str(
        data_key="created",
        example=current_datetime_in_iso8601(),
        description="Proof created date time in ISO 8601 format",
        required=False,
    )

    # Verification method
    verification_method = fields.Str(
        data_key="verificationMethod",
        example="did:mydata:123456789abcdefghi",
        description="Verification method",
        required=False,
    )

    # Proof purpose
    proof_purpose = fields.Str(
        data_key="proofPurpose",
        example="contractAgreement",
        description="Proof purpose",
        required=False,
    )

    # Proof value
    proof_value = fields.Str(
        data_key="proofValue",
        example="123456789abcdefghi",
        description="Proof value",
        required=False,
    )


class DataAgreementDummy(BaseModel):
    """
    Data agreement dummy model class
    """

    class Meta:
        # Schema class
        schema_class = "DataAgreementDummySchema"

        # Unknown fields are excluded
        unknown = EXCLUDE

    def __init__(self, *, dummy_id: str = None, **kwargs):
        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.dummy_id = dummy_id


class DataAgreementDummySchema(BaseModelSchema):
    """
    Data agreement dummy schema class
    """

    class Meta:
        # Model class
        model_class = DataAgreementDummy

    # Dummy identifier
    dummy_id = fields.Str(
        data_key="id",
        example="did:mydata:123456789abcdefghi#1",
        description="Dummy identifier",
        required=False,
    )


class DataAgreementEvent(BaseModel):
    """
    Data agreement event model class
    """

    # States
    STATE_ACCEPT = "accept"
    STATE_REJECT = "reject"
    STATE_OFFER = "offer"
    STATE_TERMINATE = "terminate"

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
        did: str = None,
        state: str = None,
        **kwargs
    ):
        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.event_id = event_id
        self.time_stamp = time_stamp
        self.did = did
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
        example="did:mydata:123456789abcdefghi#1",
        description="Data agreement event identifier",
    )

    # Time stamp
    time_stamp = fields.Str(
        data_key="time_stamp",
        example=str(
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        ),
        description="Data agreement event timestamp in ISO 8601 UTC date time format",
    )

    # Event origin DID
    did = fields.Str(
        data_key="did", description="MyData decentralised identifier", **MYDATA_DID
    )

    # State
    state = fields.Str(description="State of the event", example="capture")


class DataAgreementNegotiationOfferBody(BaseModel):
    """Data Agreement Negotiation Offer Body"""

    class Meta:
        """Data Agreement Negotiation Offer Body metadata"""

        schema_class = "DataAgreementNegotiationOfferBodySchema"

    def __init__(
        self,
        *,
        context: typing.List[str],
        data_agreement_id: str = None,
        data_agreement_version: int = None,
        data_agreement_template_id: str = None,
        data_agreement_template_version: int = None,
        pii_controller_name: str = None,
        pii_controller_url: str = None,
        usage_purpose: str = None,
        usage_purpose_description: str = None,
        legal_basis: str = None,
        method_of_use: str = None,
        data_policy: DataAgreementDataPolicy = None,
        personal_data: typing.List[DataAgreementPersonalData] = None,
        dpia: DataAgreementDPIA = None,
        proof: DataAgreementProof = None,
        event: typing.List[DataAgreementEvent] = None,
        principle_did: str = None,
        **kwargs
    ):
        """Data Agreement Negotiation Offer Body init"""

        super().__init__(**kwargs)

        # Set attributes
        self.context = context
        self.data_agreement_id = data_agreement_id
        self.data_agreement_version = data_agreement_version
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
        self.proof = proof
        self.event = event
        self.principle_did = principle_did


class DataAgreementNegotiationOfferBodySchema(BaseModelSchema):
    """Data Agreement Negotiation Offer Body schema"""

    class Meta:
        """Data Agreement Negotiation Offer Body schema metadata"""

        model_class = DataAgreementNegotiationOfferBody

    # Context
    context = fields.List(
        fields.Str(),
        example=[DATA_AGREEMENT_V1_SCHEMA_CONTEXT, ED25519_2018_CONTEXT_URL],
        data_key="@context",
        description="Context",
    )

    # Data agreement id
    data_agreement_id = fields.Str(
        data_key="id", example=UUIDFour.EXAMPLE, description="Data agreement identifier"
    )

    # Data agreement version
    data_agreement_version = fields.Int(
        data_key="version", example=1, description="Data agreement version"
    )

    # Data agreement template id
    data_agreement_template_id = fields.Str(
        data_key="template_id",
        example=UUIDFour.EXAMPLE,
        description="Data agreement template identifier",
    )

    # Data agreement template version
    data_agreement_template_version = fields.Int(
        data_key="template_version",
        example=1,
        description="Data agreement template version",
    )

    # Data agreement data controller name
    # i.e. Organization name of the data controller
    pii_controller_name = fields.Str(
        data_key="data_controller_name",
        example="Happy Shopping AB",
        description="PII controller name",
    )

    # Data agreement data controller URL
    pii_controller_url = fields.Str(
        data_key="data_controller_url",
        example="https://www.happyshopping.com",
        description="PII controller URL",
    )

    # Data agreement usage purpose
    usage_purpose = fields.Str(
        data_key="purpose",
        example="Customized shopping experience",
        description="Usage purpose title",
        required=True,
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
    data_policy = fields.Nested(
        DataAgreementDataPolicySchema, required=True, description="Data policy"
    )

    # Data agreement personal data (attributes)
    personal_data = fields.List(
        fields.Nested(DataAgreementPersonalDataSchema),
        required=True,
        description="Personal data (attributes)",
    )

    # Data agreement DPIA metadata
    dpia = fields.Nested(DataAgreementDPIASchema, description="DPIA metadata")

    # Data agreement events
    event = fields.List(fields.Nested(DataAgreementEventSchema))

    # Data agreement proof
    proof = fields.Nested(DataAgreementProofSchema)

    # Data agreement principle did
    principle_did = fields.Str(
        data_key="data_subject_did",
        example="did:mydata:123456789abcdefghi",
        description="Principle did",
    )
