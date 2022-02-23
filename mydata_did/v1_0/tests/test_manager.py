import uuid

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from aries_cloudagent.issuer.base import BaseIssuer, IssuerError
from aries_cloudagent.ledger.base import BaseLedger
from aries_cloudagent.ledger.indy import IndyLedger
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.basic import BasicWallet
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.basic import BasicStorage
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.messaging.util import str_to_epoch

from ..utils.util import bool_to_str, int_to_semver_str

from ..manager import ADAManager, ADAManagerError
from ..models.exchange_records.data_agreement_personal_data_record import DataAgreementPersonalDataRecord
from ..models.data_agreement_model import DataAgreementPersonalData, DataAgreementPersonalDataRestriction


class TestManager(AsyncTestCase):
    async def setUp(self):

        self.wallet = async_mock.MagicMock()
        self.wallet.type = "indy"

        self.issuer = async_mock.MagicMock(BaseIssuer)
        self.ledger = IndyLedger("name", self.wallet)

        self.context = InjectionContext(enforce_typing=False)
        self.context.injector.bind_instance(BaseIssuer, self.issuer)
        self.context.injector.bind_instance(BaseLedger, self.ledger)
        self.context.injector.bind_instance(BaseWallet, self.wallet)

        self.manager = ADAManager(self.context)

    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger._context_open")
    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger._context_close")
    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger._submit")
    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger.create_and_send_schema")
    async def test_create_schema_def_and_anchor_to_ledger(
        self,
        mock_create_and_send_schema,
        mock_submit,
        mock_close,
        mock_open,
    ):
        mock_create_and_send_schema.return_value = (
            "schema_issuer_did:name:1.0.0", {})

        (schema_id, schema_def) = await self.manager.create_schema_def_and_anchor_to_ledger(
            schema_name="name",
            schema_version=1,
            attributes=["name", "age"],
        )

        assert schema_id == "schema_issuer_did:name:1.0.0"
        assert schema_def == {}

        self.context.injector.clear_binding(BaseLedger)

        with self.assertRaises(ADAManagerError) as ctx:
            (schema_id, schema_def) = await self.manager.create_schema_def_and_anchor_to_ledger(
                schema_name="name",
                schema_version=1,
                attributes=["name", "age"],
            )

        self.assertTrue(
            "No ledger available" in str(ctx.exception),
        )

        mock_create_and_send_schema.side_effect = IssuerError("IssuerError")

        self.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(ADAManagerError) as ctx:
            (schema_id, schema_def) = await self.manager.create_schema_def_and_anchor_to_ledger(
                schema_name="name",
                schema_version=1,
                attributes=["name", "age"],
            )

        self.assertTrue(
            "IssuerError" in str(ctx.exception),
        )

    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger._context_open")
    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger._context_close")
    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger._submit")
    @async_mock.patch("aries_cloudagent.ledger.indy.IndyLedger.create_and_send_credential_definition")
    async def test_create_cred_def_and_anchor_to_ledger(
        self,
        mock_create_and_send_credential_definition,
        mock_submit,
        mock_close,
        mock_open,
    ):
        test_cred_def_id = "issuer_did:3:CL:102:default"
        test_cred_def = {
            "id": test_cred_def_id,
            "schema": "schema_issuer_did:name:1.0.0",
            "type": "CL",
            "tag": "default",
            "value": {},
            "ver": "1.0",
        }
        test_novel = True
        mock_create_and_send_credential_definition.return_value = (
            test_cred_def_id, test_cred_def, test_novel)

        (cred_def_id, cred_def, novel) = await self.manager.create_cred_def_and_anchor_to_ledger(
            schema_id="schema_issuer_did:name:1.0.0",
            tag="default",
            support_revocation=False,
        )

        assert cred_def_id == test_cred_def_id
        assert cred_def == test_cred_def
        assert novel == test_novel

        self.context.injector.clear_binding(BaseLedger)

        with self.assertRaises(ADAManagerError) as ctx:

            (cred_def_id, cred_def, novel) = await self.manager.create_cred_def_and_anchor_to_ledger(
                schema_id="schema_issuer_did:name:1.0.0",
                tag="default",
                support_revocation=False,
            )

        self.assertTrue(
            "No ledger available" in str(ctx.exception),
        )

        mock_create_and_send_credential_definition.side_effect = IssuerError(
            "IssuerError")

        self.context.injector.bind_instance(BaseLedger, self.ledger)

        with self.assertRaises(ADAManagerError) as ctx:

            (cred_def_id, cred_def, novel) = await self.manager.create_cred_def_and_anchor_to_ledger(
                schema_id="schema_issuer_did:name:1.0.0",
                tag="default",
                support_revocation=False,
            )

        self.assertTrue(
            "IssuerError" in str(ctx.exception),
        )

    async def test_construct_proof_request_from_personal_data(self):

        usage_purpose = "Verify Covid19 Test Result"
        usage_purpose_description = "Collect Covid19 Test Result from customers to permit entry."
        data_agreement_template_version = int_to_semver_str(1)

        da_pd_records = [
            DataAgreementPersonalDataRecord(
                attribute_name="Covid IN Beneficiary Name",
                attribute_category="Covid19",
                attribute_sensitive=bool_to_str(True),
                attribute_description="Full name of the individual",
                restrictions=[
                    {
                        "schema_id": "issuer_did:name:1.0.0",
                        "cred_def_id": "issuer_did:3:CL:102:default",
                    }
                ]
            ),
            DataAgreementPersonalDataRecord(
                attribute_name="Covid IN Age",
                attribute_category="Covid19",
                attribute_sensitive=bool_to_str(True),
                attribute_description="Age of the individual",
            )
        ]

        proof_request = self.manager.construct_proof_request_from_personal_data(
            usage_purpose=usage_purpose,
            usage_purpose_description=usage_purpose_description,
            data_agreement_template_version=data_agreement_template_version,
            personal_data=da_pd_records,
        )

        assert proof_request["name"] == usage_purpose
        assert proof_request["version"] == data_agreement_template_version
        assert proof_request["comment"] == usage_purpose_description
        assert proof_request["requested_attributes"] == {
            "additionalProp1": {
                "name": "Covid IN Beneficiary Name",
                "restrictions": [
                    {
                        "schema_id": "issuer_did:name:1.0.0",
                        "cred_def_id": "issuer_did:3:CL:102:default",
                    }
                ],
            },
            "additionalProp2": {
                "name": "Covid IN Age",
                "restrictions": [],
            },
        }

    async def test_create_and_store_da_personal_data_in_wallet(self):
        self.storage = BasicStorage()
        self.wallet = BasicWallet()

        self.context = InjectionContext(enforce_typing=False)
        self.context.injector.bind_instance(
            BaseStorage, self.storage
        )
        self.context.injector.bind_instance(
            BaseWallet, self.wallet
        )

        self.manager = ADAManager(self.context)

        da_pd = DataAgreementPersonalData(
            attribute_name="Covid IN Beneficiary Name",
            attribute_description="Full name of the individual",
        )

        da_pd_record = await self.manager.create_and_store_da_personal_data_in_wallet(
            personal_data=da_pd,
            da_template_id=str(uuid.uuid4()),
            da_template_version=1
        )

        da_pd2 = DataAgreementPersonalData(
            attribute_name="Covid IN Age",
            attribute_description="Age of the individual",
            restrictions=[
                DataAgreementPersonalDataRestriction(
                    schema_id="issuer_did:name:1.0.0",
                    cred_def_id="issuer_did:3:CL:102:default",
                )
            ]
        )

        da_pd_record2 = await self.manager.create_and_store_da_personal_data_in_wallet(
            personal_data=da_pd2,
            da_template_id=str(uuid.uuid4()),
            da_template_version=1
        )

        da_pd_records = await DataAgreementPersonalDataRecord.query(
            self.context,
            tag_filter={}
        )

        assert len(da_pd_records) == 2
    
    async def test_serialize_personal_data_records(self):
        self.storage = BasicStorage()
        self.wallet = BasicWallet()

        self.context = InjectionContext(enforce_typing=False)
        self.context.injector.bind_instance(
            BaseStorage, self.storage
        )
        self.context.injector.bind_instance(
            BaseWallet, self.wallet
        )

        self.manager = ADAManager(self.context)


        da_pd = DataAgreementPersonalData(
            attribute_name="Covid IN Beneficiary Name",
            attribute_description="Full name of the individual",
        )

        da_pd_record = await self.manager.create_and_store_da_personal_data_in_wallet(
            personal_data=da_pd,
            da_template_id=str(uuid.uuid4()),
            da_template_version=1
        )

        da_pd_records = await DataAgreementPersonalDataRecord.query(
            self.context,
        )
        
        assert len(da_pd_records) == 1

        serialized_da_pd_records = self.manager.serialize_personal_data_record(
            personal_data_records=da_pd_records,
        )

        assert serialized_da_pd_records[0]["attribute_name"] == da_pd_record.attribute_name
        assert serialized_da_pd_records[0]["created_at"] == str_to_epoch(da_pd_record.created_at)

