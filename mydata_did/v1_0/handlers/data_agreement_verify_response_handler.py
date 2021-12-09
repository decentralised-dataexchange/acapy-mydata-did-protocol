from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.storage.error import StorageNotFoundError, StorageSearchError, StorageDuplicateError, StorageError
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from ..messages.data_agreement_verify_response import DataAgreementVerifyResponse
from ..models.exchange_records.data_agreement_record import DataAgreementV1Record
from ..manager import ADAManager, ADAManagerError
from ..utils.did.mydata_did import DIDMyData
from ..models.exchange_records.auditor_didcomm_transaction_record import AuditorDIDCommTransactionRecord

import json


class DataAgreementVerifyResponseHandler(BaseHandler):
    """
    Handler for data agreement verify response.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data agreement verify response.
        """

        # Assert if received message is of type DataAgreementVerifyResponse
        assert isinstance(context.message, DataAgreementVerifyResponse)

        self._logger.info(
            "Received data-agreement-proofs/1.0/verify-response message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if the connection is ready.
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping data-agreement-proofs/1.0/verify-response handler: %s",
                context.message_receipt.sender_did,
            )
            return

        data_agreement_verify_response = context.message

        # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Retrieve auditor didcomm transaction record
        try:
            auditor_didcomm_transaction_record: AuditorDIDCommTransactionRecord = await AuditorDIDCommTransactionRecord.retrieve_by_tag_filter(
                context,
                {
                    "thread_id": data_agreement_verify_response._thread_id
                }
            )

            # Update the auditor didcomm transaction record
            auditor_didcomm_transaction_record.messages_list.append(
                data_agreement_verify_response.serialize()
            )

            await auditor_didcomm_transaction_record.save(context)

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # No record found
            self._logger.debug(
                "Failed to process data-agreement-proofs/1.0/verify-response message; "
                "No auditor didcomm transaction record found for thread_id: %s", data_agreement_verify_response._thread_id
            )
            return
