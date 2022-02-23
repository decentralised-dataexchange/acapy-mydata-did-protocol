import typing

from asynctest import TestCase as AsyncTestCase
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.basic import BasicStorage
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.basic import BasicWallet
from aries_cloudagent.config.injection_context import InjectionContext

from ....manager import ADAManager

from ..data_agreement_record import DataAgreementV1Record


class TestDataAgreementV1Record(AsyncTestCase):
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

        self.data_agreement_v1_record = DataAgreementV1Record(
            data_agreement_id="123",
            state=DataAgreementV1Record.STATE_PREPARATION,
            method_of_use=DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE,
            data_agreement={},
            publish_flag="false",
            delete_flag="true",
            schema_id="schema_id",
            cred_def_id="cred_def_id",
            data_agreement_proof_presentation_request={},
        )

    def test_delete_flag_property(self):
        assert self.data_agreement_v1_record._delete_flag == True

    def test_publish_flag_property(self):
        assert self.data_agreement_v1_record._publish_flag == False

    def test_is_deleted_property(self):
        assert self.data_agreement_v1_record.is_deleted == True

    def test_is_published_property(self):
        self.data_agreement_v1_record._delete_flag = False
        self.data_agreement_v1_record._publish_flag = True

        assert self.data_agreement_v1_record.is_published == True
    
    async def test_save_data_agreement_v1_record (self):

        assert self.data_agreement_v1_record.data_agreement_record_id == None

        await self.data_agreement_v1_record.save(self.context)

        da_v1_records: typing.List[DataAgreementV1Record] = await self.data_agreement_v1_record.query(
            self.context,
        )

        assert len(da_v1_records) == 1
