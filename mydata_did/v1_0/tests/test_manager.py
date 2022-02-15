import uuid

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.basic import BasicStorage
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.basic import BasicWallet
from aries_cloudagent.config.injection_context import InjectionContext

from ..manager import ADAManager


class TestADAManager(AsyncTestCase):
    def setUp(self):
        self.storage = BasicStorage()
        self.wallet = BasicWallet()

        self.context = InjectionContext(enforce_typing=False)
        self.context.injector.bind_instance(BaseStorage, self.storage)
        self.context.injector.bind_instance(BaseWallet, self.wallet)

        self.manager = ADAManager(self.context)

    async def test_store_data_agreement_instance_metadata(self):

        data_agreement_id = str(uuid.uuid4())
        data_agreement_template_id = "c0c68a75-805b-4467-b425-ff968cd8d7eb"
        method_of_use = "data-source"
        data_exchange_record_id = str(uuid.uuid4())

        await self.manager.store_data_agreement_instance_metadata(
            data_agreement_id=data_agreement_id,
            data_agreement_template_id=data_agreement_template_id,
            method_of_use=method_of_use,
            data_exchange_record_id=data_exchange_record_id,
        )

        await self.manager.store_data_agreement_instance_metadata(
            data_agreement_id=data_agreement_id,
            data_agreement_template_id=data_agreement_template_id,
            method_of_use=method_of_use,
            data_exchange_record_id=data_exchange_record_id,
        )

        storage_records = await self.manager.query_data_agreement_instance_metadata(
            tag_query={}
        )

        assert len(storage_records) == 2
