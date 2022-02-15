from asynctest import TestCase as AsyncTestCase

from ..data_agreement_model import DataAgreementV1Schema, DataAgreementV1
from marshmallow.exceptions import ValidationError


class TestDataAgreementV1Model(AsyncTestCase):

    def test_data_agreement_model(self):
        data_agreement_dict = {
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

        data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(data_agreement_dict)

        assert data_agreement.pii_controller_name == "XYZ Corp"

        assert len(data_agreement.personal_data) == 1

        self.assertIsNone(
            data_agreement.personal_data[0].attribute_id, "Attribute ID should be None")

        data_agreement_dict.pop("data_controller_name")
        with self.assertRaises(ValidationError) as ctx:
            data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(data_agreement_dict)

        self.assertTrue(
            "Missing data for required field." in str(ctx.exception))
