from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from ..messages.data_agreement_verify import DataAgreementVerify
from ..messages.data_agreement_verify_response import DataAgreementVerifyResponse
from ..models.exchange_records.data_agreement_record import DataAgreementV1Record
from ..manager import ADAManager, ADAManagerError
from ..utils.did.mydata_did import DIDMyData
from ..utils.jsonld.data_agreement import verify_data_agreement, verify_data_agreement_with_proof_chain
from ..models.exchange_records.auditor_didcomm_transaction_record import AuditorDIDCommTransactionRecord

import json


class DataAgreementVerifyHandler(BaseHandler):
    """
    Handler for data agreement verify request.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data agreement verify.
        """

        # Assert if received message is of type DataAgreementVerify
        assert isinstance(context.message, DataAgreementVerify)

        self._logger.info(
            "Received data-agreement-proofs/1.0/verify-request message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if the connection is ready.
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping data-agreement-proofs/1.0/verify-request handler: %s",
                context.message_receipt.sender_did,
            )
            return

        data_agreement_verify_request = context.message
        data_agreement = data_agreement_verify_request.body.data_agreement

        # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Create auditor didcomm transaction record
        auditor_didcomm_transaction_record = AuditorDIDCommTransactionRecord(
            thread_id=data_agreement_verify_request._id,
            messages_list=[data_agreement_verify_request.serialize()],
            connection_id=context.connection_record.connection_id,
        )

        await auditor_didcomm_transaction_record.save(context)

        try:

            data_controller_did = DIDMyData.from_did(
                data_agreement.event[0].did)
            principle_did = DIDMyData.from_did(data_agreement.principle_did)

            # Verify data controller did
            # Fetch controller did from did registry
            await ada_manager.resolve_remote_mydata_did(mydata_did=data_controller_did.did)

            valid = False

            if len(data_agreement.event) == 3:
                verkeys = []

                for event in data_agreement.event:
                    temp_verkey = DIDMyData.from_did(event.did).public_key_b58
                    verkeys.append(temp_verkey)

                valid = await verify_data_agreement(
                    data_agreement.serialize(),
                    verkeys[-1],
                    wallet,
                    drop_proof_chain=False
                )

                # drop last event and proof
                data_agreement.event.pop()
                data_agreement.proof_chain.pop()

            if len(data_agreement.event) == 2:
                # Verify signatures on data agreement
                valid = await verify_data_agreement_with_proof_chain(
                    data_agreement.serialize(),
                    [
                        data_controller_did.public_key_b58,
                        principle_did.public_key_b58
                    ],
                    wallet
                )

                # drop last event and proof
                data_agreement.event.pop()
                data_agreement.proof_chain.pop()

                # Convert proof chain to single proof
                data_agreement.proof = data_agreement.proof_chain[0]
                data_agreement.proof_chain = None

            if len(data_agreement.event) == 1:
                # Verify signatures on data agreement
                valid = await verify_data_agreement(
                    data_agreement.serialize(),
                    data_controller_did.public_key_b58,
                    wallet
                )

            if valid:

                # Verification successful

                self._logger.info(
                    "Data-agreement-proofs/1.0/verify-request message verification successful: \n%s",
                    json.dumps(data_agreement.serialize(), indent=4)
                )

                data_agreement_verify_response = DataAgreementVerifyResponse(
                    status="OK",
                    explain=f"Signature verification successful."
                )

                data_agreement_verify_response.assign_thread_id(
                    thid=data_agreement_verify_request._id
                )

                auditor_didcomm_transaction_record.messages_list.append(
                    data_agreement_verify_response.serialize()
                )

                await auditor_didcomm_transaction_record.save(context)

                await responder.send_reply(data_agreement_verify_response)

            else:

                # Verification failed

                data_agreement_verify_response = DataAgreementVerifyResponse(
                    status="NOT OK",
                    explain=f"Signature verification failed."
                )

                data_agreement_verify_response.assign_thread_id(
                    thid=data_agreement_verify_request._id
                )

                auditor_didcomm_transaction_record.messages_list.append(
                    data_agreement_verify_response.serialize()
                )

                await auditor_didcomm_transaction_record.save(context)

                await responder.send_reply(data_agreement_verify_response)

        except (ADAManagerError, Exception) as err:
            self._logger.exception("Failed to verify data agreement")

            data_agreement_verify_response = DataAgreementVerifyResponse(
                status="NOT OK",
                explain=f"Failed to verify data agreement: {err}"
            )

            data_agreement_verify_response.assign_thread_id(
                thid=data_agreement_verify_request._id
            )

            auditor_didcomm_transaction_record.messages_list.append(
                data_agreement_verify_response.serialize()
            )

            await auditor_didcomm_transaction_record.save(context)

            await responder.send_reply(data_agreement_verify_response)

            return
