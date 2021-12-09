from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext, HandlerException
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from ..messages.data_agreement_terminate import DataAgreementTerminationTerminateMessage
from ..messages.data_agreement_terminate_ack import DataAgreementTerminationAck
from ..manager import ADAManager
from ..models.data_agreement_termination_terminate_model import DataAgreementTerminationTerminateBody
from ..models.exchange_records.data_agreement_record import DataAgreementV1Record
from ..models.data_agreement_instance_model import DataAgreementInstance, DataAgreementInstanceSchema
from ..utils.did.mydata_did import DIDMyData
from ..utils.jsonld.data_agreement import verify_data_agreement
from ..messages.problem_report import (
    DataAgreementTerminationProblemReport,
    DataAgreementTerminationProblemReportReason
)

from ...patched_protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange
)

from ...patched_protocols.present_proof.v1_0.models.presentation_exchange import (
    V10PresentationExchange
)

import json
import datetime


class DataAgreementTerminationTerminateMessageHandler(BaseHandler):
    """Handler for data-agreement-termination/1.0/terminate message."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for data-agreement-termination/1.0/terminate message."""

        # Assert that the message is of the correct type
        assert isinstance(
            context.message, DataAgreementTerminationTerminateMessage)

        self._logger.info(
            "Received data-agreement-termination/1.0/terminate message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if connection is ready
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping data-agreement-termination/1.0/terminate handler: %s",
                context.message_receipt.sender_did,
            )
            return

        data_agreement_termination_terminate_message = context.message
        data_agreement_termination_terminate_message_body: DataAgreementTerminationTerminateBody = data_agreement_termination_terminate_message.body

        # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Fetch the data agreement instance metadata
        data_agreement_instance_metadata_records = await ada_manager.query_data_agreement_instance_metadata(
            tag_query={
                'data_agreement_id': data_agreement_termination_terminate_message_body.data_agreement_id,
            }
        )

        # Check if there is a data agreement instance metadata record
        if not data_agreement_instance_metadata_records:
            self._logger.info(
                "Data agreement not found; Failed to handle terminate message for data agreement: %s",
                data_agreement_termination_terminate_message_body.data_agreement_id,
            )
            return

        if len(data_agreement_instance_metadata_records) > 1:
            self._logger.info(
                "Duplicate data agreement records found; Failed to handle terminate message for data agreement: %s",
                data_agreement_termination_terminate_message_body.data_agreement_id,
            )
            return

        data_agreement_instance_metadata_record: StorageRecord = data_agreement_instance_metadata_records[
            0]

        # Identify the method of use

        if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:

            # Fetch exchante record (credential exchange if method of use is "data-source")
            tag_filter = {}
            post_filter = {
                "data_agreement_id": data_agreement_termination_terminate_message_body.data_agreement_id
            }
            records = await V10CredentialExchange.query(context, tag_filter, post_filter)

            if not records:
                self._logger.info(
                    "Credential exchange record not found; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )
                return

            if len(records) > 1:
                self._logger.info(
                    "Duplicate credential exchange records found; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )
                return

            cred_ex_record: V10CredentialExchange = records[0]

            # Check if data agreement is in "accept" status
            if cred_ex_record.data_agreement_status != V10CredentialExchange.DATA_AGREEMENT_ACCEPT:
                self._logger.info(
                    "Credential exchange record not in offer sent state; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )
                return

            # Reconstruct the data agreement

            # Deserialise data agreement
            data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
                cred_ex_record.data_agreement
            )

            # Check if terminate message is signed by data agreement principle did
            if data_agreement_instance.principle_did != data_agreement_termination_terminate_message_body.proof.verification_method:
                self._logger.info(
                    "Data agreement principle DID does not match sender DID; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )

                # Send problem report.

                problem_report = DataAgreementTerminationProblemReport(
                    from_did=data_agreement_termination_terminate_message.to_did,
                    to_did=data_agreement_termination_terminate_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    problem_code=DataAgreementTerminationProblemReportReason.PRINCIPLE_DID_INVALID.value,
                    explain=f"Data agreement principle DID does not match sender DID; Failed to process terminate message for data agreement: {data_agreement_termination_terminate_message.body.data_agreement_id}",
                    data_agreement_id=data_agreement_termination_terminate_message_body.data_agreement_id
                )

                problem_report.assign_thread_id(
                    thid=data_agreement_termination_terminate_message._id
                )

                # Update credential exchange record with data agreement metadata
                cred_ex_record.data_agreement_problem_report = problem_report.serialize()
                cred_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
                await cred_ex_record.save(context)

                await responder.send_reply(problem_report)

                return

            # Update data agreement event with terminate event
            data_agreement_instance.event.append(
                data_agreement_termination_terminate_message_body.event
            )

            # Update data agreement proof chain with terminate proof
            data_agreement_instance.proof_chain.append(
                data_agreement_termination_terminate_message_body.proof
            )

            # Verify signatures on data agreement
            verkeys = []

            for event in data_agreement_instance.event:
                temp_verkey = DIDMyData.from_did(event.did).public_key_b58
                verkeys.append(temp_verkey)

            valid = await verify_data_agreement(
                data_agreement_instance.serialize(),
                verkeys[-1],
                wallet,
                drop_proof_chain=False
            )

            if not valid:
                self._logger.error(
                    "Data agreement terminate verification failed"
                )

                # Send problem report

                problem_report = DataAgreementTerminationProblemReport(
                    from_did=data_agreement_termination_terminate_message.to_did,
                    to_did=data_agreement_termination_terminate_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    problem_code=DataAgreementTerminationProblemReportReason.SIGNATURE_VERIFICATION_FAILED.value,
                    explain=f"Data agreement terminate verification failed; Failed to process terminate message for data agreement: {data_agreement_termination_terminate_message.body.data_agreement_id}",
                    data_agreement_id=data_agreement_termination_terminate_message_body.data_agreement_id
                )

                problem_report.assign_thread_id(
                    thid=data_agreement_termination_terminate_message._id
                )

                # Update credential exchange record with data agreement metadata
                cred_ex_record.data_agreement_problem_report = problem_report.serialize()
                cred_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
                await cred_ex_record.save(context)

                await responder.send_reply(problem_report)

                raise HandlerException(
                    "Data agreement terminate signature verification failed"
                )

            # Update credential exchange record with data agreement metadata
            cred_ex_record.data_agreement = data_agreement_instance.serialize()
            cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_TERMINATE

            await cred_ex_record.save(context)

            # Construct terminate ack message
            data_agreement_terminate_ack = DataAgreementTerminationAck(
                status="TERMINATE OK"
            )

            data_agreement_terminate_ack.assign_thread_id(
                thid=data_agreement_termination_terminate_message._id
            )

            await responder.send_reply(data_agreement_terminate_ack)

        if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:

            # Fetch exchange record (presentation exchange if method of use is "data-using-service")
            tag_filter = {}
            post_filter = {
                "data_agreement_id": data_agreement_termination_terminate_message_body.data_agreement_id
            }
            records = await V10PresentationExchange.query(context, tag_filter, post_filter)

            if not records:
                self._logger.info(
                    "Presentation exchange record not found; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )
                return

            if len(records) > 1:
                self._logger.info(
                    "Duplicate presentation exchange records found; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )
                return

            pres_ex_record: V10PresentationExchange = records[0]

            # Check if data agreement is in "accept" status
            if pres_ex_record.data_agreement_status != V10PresentationExchange.DATA_AGREEMENT_ACCEPT:
                self._logger.info(
                    "Presentation exchange record not in offer sent state; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )
                return

            # Reconstruct the data agreement

            # Deserialise data agreement
            data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
                pres_ex_record.data_agreement
            )

            # Check if terminate message is signed by data agreement principle did
            if data_agreement_instance.principle_did != data_agreement_termination_terminate_message_body.proof.verification_method:
                self._logger.info(
                    "Data agreement principle DID does not match sender DID; Failed to handle terminate message for data agreement: %s",
                    data_agreement_termination_terminate_message_body.data_agreement_id,
                )

                # Send problem report.

                problem_report = DataAgreementTerminationProblemReport(
                    from_did=data_agreement_termination_terminate_message.to_did,
                    to_did=data_agreement_termination_terminate_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    problem_code=DataAgreementTerminationProblemReportReason.PRINCIPLE_DID_INVALID.value,
                    explain=f"Data agreement principle DID does not match sender DID; Failed to process terminate message for data agreement: {data_agreement_termination_terminate_message.body.data_agreement_id}",
                    data_agreement_id=data_agreement_termination_terminate_message_body.data_agreement_id
                )

                problem_report.assign_thread_id(
                    thid=data_agreement_termination_terminate_message._id
                )

                # Update presentation exchange record with data agreement metadata
                pres_ex_record.data_agreement_problem_report = problem_report.serialize()
                pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
                await pres_ex_record.save(context)

                await responder.send_reply(problem_report)

                return

            # Update data agreement event with terminate event
            data_agreement_instance.event.append(
                data_agreement_termination_terminate_message_body.event
            )

            # Update data agreement proof chain with terminate proof
            data_agreement_instance.proof_chain.append(
                data_agreement_termination_terminate_message_body.proof
            )

            # Verify signatures on data agreement
            verkeys = []

            for event in data_agreement_instance.event:
                temp_verkey = DIDMyData.from_did(event.did).public_key_b58
                verkeys.append(temp_verkey)

            valid = await verify_data_agreement(
                data_agreement_instance.serialize(),
                verkeys[-1],
                wallet,
                drop_proof_chain=False
            )

            if not valid:
                self._logger.error(
                    "Data agreement terminate verification failed"
                )

                # Send problem report

                problem_report = DataAgreementTerminationProblemReport(
                    from_did=data_agreement_termination_terminate_message.to_did,
                    to_did=data_agreement_termination_terminate_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    problem_code=DataAgreementTerminationProblemReportReason.SIGNATURE_VERIFICATION_FAILED.value,
                    explain=f"Data agreement terminate verification failed; Failed to process terminate message for data agreement: {data_agreement_termination_terminate_message.body.data_agreement_id}",
                    data_agreement_id=data_agreement_termination_terminate_message_body.data_agreement_id
                )

                problem_report.assign_thread_id(
                    thid=data_agreement_termination_terminate_message._id
                )

                # Update presentation exchange record with data agreement metadata
                pres_ex_record.data_agreement_problem_report = problem_report.serialize()
                pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
                await pres_ex_record.save(context)

                await responder.send_reply(problem_report)

                raise HandlerException(
                    "Data agreement terminate signature verification failed"
                )

            # Update presentation exchange record with data agreement metadata
            pres_ex_record.data_agreement = data_agreement_instance.serialize()
            pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_TERMINATE

            await pres_ex_record.save(context)

            # Construct terminate ack message
            data_agreement_terminate_ack = DataAgreementTerminationAck(
                status="TERMINATE OK"
            )

            data_agreement_terminate_ack.assign_thread_id(
                thid=data_agreement_termination_terminate_message._id
            )

            await responder.send_reply(data_agreement_terminate_ack)
