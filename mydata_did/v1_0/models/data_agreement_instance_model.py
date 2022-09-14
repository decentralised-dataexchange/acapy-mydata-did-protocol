import typing

from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from aries_cloudagent.messaging.valid import UUIDFour
from marshmallow import fields, validate
from mydata_did.v1_0.models.data_agreement_model import (
    DATA_AGREEMENT_V1_SCHEMA_CONTEXT,
    DataAgreementDataPolicy,
    DataAgreementDataPolicySchema,
    DataAgreementDPIA,
    DataAgreementDPIASchema,
    DataAgreementPersonalData,
    DataAgreementPersonalDataSchema,
)
from mydata_did.v1_0.models.data_agreement_negotiation_offer_model import (
    DataAgreementEvent,
    DataAgreementEventSchema,
    DataAgreementProof,
    DataAgreementProofSchema,
)
from mydata_did.v1_0.utils.jsonld import ED25519_2018_CONTEXT_URL


class DataAgreementInstance(BaseModel):
    """Data Agreement instance Body"""

    class Meta:
        """Data Agreement instance metadata"""

        schema_class = "DataAgreementInstanceSchema"

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
        event: typing.List[DataAgreementEvent] = None,
        proof_chain: typing.List[DataAgreementProof] = None,
        principle_did: str = None,
        proof: DataAgreementProof = None,
        **kwargs
    ):
        """Data Agreement instance init"""

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
        self.proof_chain = proof_chain
        self.principle_did = principle_did
        self.event = event
        self.proof = proof


class DataAgreementInstanceSchema(BaseModelSchema):
    """Data Agreement instance schema"""

    class Meta:
        """Data Agreement instance metadata"""

        model_class = DataAgreementInstance

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

    # Data agreement proof chain
    proof_chain = fields.List(
        fields.Nested(DataAgreementProofSchema),
        description="Data agreement proof chain",
        data_key="proofChain",
    )

    # Data agreement principle did
    principle_did = fields.Str(
        data_key="data_subject_did",
        example="did:mydata:123456789abcdefghi",
        description="Principle did",
    )

    # Data agreement proof
    proof = fields.Nested(DataAgreementProofSchema, required=False)
