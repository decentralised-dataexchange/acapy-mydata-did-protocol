from asynctest import TestCase as AsyncTestCase

from ..models.exchange_records.data_agreement_record import DataAgreementV1Record


class TestDataAgreementV1Record(AsyncTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.data_agreement_v1_record = DataAgreementV1Record(
            data_agreement_id="123",
            state=DataAgreementV1Record.STATE_PREPARATION,
            method_of_use=DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE,
            data_agreement={},
            publish_flag="False",
            delete_flag="True",
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
