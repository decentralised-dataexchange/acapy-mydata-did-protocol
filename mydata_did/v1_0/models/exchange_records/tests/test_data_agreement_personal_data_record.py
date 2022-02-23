import typing

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.basic import BasicStorage
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.basic import BasicWallet
from aries_cloudagent.config.injection_context import InjectionContext

from ....manager import ADAManager
from ...data_agreement_model import DataAgreementPersonalData
from ..data_agreement_personal_data_record import DataAgreementPersonalDataRecord

class TestDataAgreementPersonalDataRecord(AsyncTestCase):

    def setUp(self) -> None:
        
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
    
    async def test_personal_data_record_without_restrictions(self):
        da_personal_data_1 = DataAgreementPersonalDataRecord(
            attribute_name="First Name",
            attribute_sensitive=True,
            attribute_category="Biographic",
            attribute_description="First name of the person"
        )

        da_personal_data_2 = DataAgreementPersonalDataRecord(
            attribute_name="Last Name",
            attribute_sensitive=True,
            attribute_category="Biographic",
            attribute_description="Last name of the person"
        )

        await da_personal_data_1.save(self.context)
        await da_personal_data_2.save(self.context)

        da_personal_data_records: typing.List[DataAgreementPersonalDataRecord] = await DataAgreementPersonalDataRecord.query(
            self.context,
            {}
        )

        self.assertEqual(len(da_personal_data_records), 2)
    
    async def test_personal_data_record_with_restrictions(self):
        da_personal_data_1 = DataAgreementPersonalDataRecord(
            attribute_name="First Name",
            attribute_sensitive=True,
            attribute_category="Biographic",
            attribute_description="First name of the person",
            restrictions=[
                {
                    "schema_id": "issuer_did:name:1.0.0",
                    "cred_def_id": "issuer_did:3:CL:19:tag",
                }
            ]
        )

        await da_personal_data_1.save(self.context)

        da_personal_data_records: typing.List[DataAgreementPersonalDataRecord] = await DataAgreementPersonalDataRecord.query(
            self.context,
            {}
        )

        self.assertEqual(len(da_personal_data_records), 1)

        da_personal_data_2 = DataAgreementPersonalDataRecord(
            attribute_name="Last Name",
            attribute_sensitive=True,
            attribute_category="Biographic",
            attribute_description="Last name of the person",
            restrictions=[]
        )

        await da_personal_data_2.save(self.context)

        da_personal_data_records: typing.List[DataAgreementPersonalDataRecord] = await DataAgreementPersonalDataRecord.query(
            self.context,
            {}
        )

        self.assertEqual(len(da_personal_data_records), 2)

        da_personal_data_3 = DataAgreementPersonalDataRecord(
            attribute_name="Age",
            attribute_sensitive=True,
            attribute_category="Biographic",
            attribute_description="Age of the person",
            restrictions=[{}]
        )

        await da_personal_data_3.save(self.context)

        da_personal_data_records: typing.List[DataAgreementPersonalDataRecord] = await DataAgreementPersonalDataRecord.query(
            self.context,
            {}
        )

        self.assertEqual(len(da_personal_data_records), 3)
    
    async def test_personal_data_record_serialize(self):
        da_personal_data_1 = DataAgreementPersonalDataRecord(
            attribute_name="First Name",
            attribute_sensitive=True,
            attribute_category="Biographic",
            attribute_description="First name of the person",
            restrictions=[
                {
                    "schema_id": "issuer_did:name:1.0.0",
                    "cred_def_id": "issuer_did:3:CL:19:tag",
                }
            ]
        )

        await da_personal_data_1.save(self.context)

        self.assertTrue(da_personal_data_1.serialize().get("restrictions") == [
            {
                "schema_id": "issuer_did:name:1.0.0",
                "cred_def_id": "issuer_did:3:CL:19:tag",
            }
        ])

        da_personal_data_2 = DataAgreementPersonalDataRecord(
            attribute_name="Last Name",
            attribute_sensitive=True,
            attribute_category="Biographic",
            attribute_description="Last name of the person",
            restrictions=[
                {
                    "attrib": "value",
                }
            ]
        )

        await da_personal_data_2.save(self.context)

        self.assertTrue(da_personal_data_2.serialize().get("restrictions") == [{}])