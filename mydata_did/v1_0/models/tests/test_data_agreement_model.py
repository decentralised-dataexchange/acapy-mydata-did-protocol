from asynctest import TestCase as AsyncTestCase

from ..data_agreement_model import (
    DataAgreementV1Schema, 
    DataAgreementV1, 
    DataAgreementPersonalData,
    DataAgreementPersonalDataRestriction,
    DataAgreementPersonalDataRestrictionSchema
)

from marshmallow.exceptions import ValidationError


class TestDataAgreementV1Model(AsyncTestCase):

    def setUp(self) -> None:
        self.data_agreement_dict = {
            "@context": "https://raw.githubusercontent.com/decentralised-dataexchange/automated-data-agreements/main/interface-specs/data-agreement-schema/v1/data-agreement-schema-context.jsonld",
            "data_controller_name": "XYZ Corp",
            "data_controller_url": "https://xyz.com",
            "purpose": "Issuance of parking permit",
            "purpose_description": "Issuance of parking permit",
            "lawful_basis": "consent",
            "method_of_use": "data-source",
            "data_policy": {
                "data_retention_period": 365,
                "policy_URL": "https://clarifyhealth.com/privacy-policy/",
                "jurisdiction": "EU",
                "industry_sector": "Retail",
                "geographic_restriction": "EU",
                "storage_location": "EU"
            },
            "personal_data": [
                {
                    "attribute_name": "First Name",
                    "attribute_sensitive": True,
                    "attribute_category": "Biographic",
                    "attribute_description": "First name of the person"
                }
            ],
            "dpia": {
                "dpia_date": "2022-02-13T15:25:18.117255+00:00",
                "dpia_summary_url": "https://org.com/dpia_results.html"
            }
        }

    def test_data_agreement_model(self):

        data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(
            self.data_agreement_dict)

        assert data_agreement.pii_controller_name == "XYZ Corp"

        assert len(data_agreement.personal_data) == 1

        self.assertIsInstance(
            data_agreement.personal_data[0], DataAgreementPersonalData)

        self.assertIsNone(
            data_agreement.personal_data[0].attribute_id, "Attribute ID should be None")

        self.data_agreement_dict.pop("data_controller_name")
        with self.assertRaises(ValidationError) as ctx:
            data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(
                self.data_agreement_dict)

        self.assertTrue(
            "Missing data for required field." in str(ctx.exception))

    def test_data_agreement_model_without_personal_data(self):
        self.data_agreement_dict.pop("personal_data")

        with self.assertRaises(ValidationError) as ctx:
            data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(
                self.data_agreement_dict)

        self.assertTrue(
            "Missing data for required field." in str(ctx.exception)
        )

    def test_data_agreement_model_with_empty_personal_data(self):
        self.data_agreement_dict["personal_data"] = []

        with self.assertRaises(ValidationError) as ctx:
            data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(
                self.data_agreement_dict)

        self.assertTrue(
            "Shorter than minimum length 1." in str(ctx.exception)
        )

    def test_data_agreement_personal_restrictions(self):
        pd_restriction_dict  = {
            "schema_id": "schema_issuer_did:name:1.0.0",
            "cred_def_id": "issuer_did:3:CL:102:default"
        }

        pd_restriction: DataAgreementPersonalDataRestriction = DataAgreementPersonalDataRestrictionSchema().load(
            pd_restriction_dict
        )

        assert pd_restriction.schema_id == "schema_issuer_did:name:1.0.0"
