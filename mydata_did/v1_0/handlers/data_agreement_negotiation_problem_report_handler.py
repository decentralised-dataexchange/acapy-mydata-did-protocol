from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from ..messages.problem_report import DataAgreementNegotiationProblemReport
from ..models.exchange_records.data_agreement_record import DataAgreementV1Record
from ..manager import ADAManager

from ...patched_protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange
)

from ...patched_protocols.present_proof.v1_0.models.presentation_exchange import (
    V10PresentationExchange
)

import json


class DataAgreementNegotiationProblemReportHandler(BaseHandler):
    """
    Handler for data agreement negotiation problem report.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data agreement negotiation problem report.
        """

        # Assert if received message is of type DataAgreementNegotiationProblemReport
        assert isinstance(context.message, DataAgreementNegotiationProblemReport)

        self._logger.info(
            "Received data-agreement-negotiation/1.0/problem-report message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if the connection is ready.
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping data-agreement-negotiation/1.0/problem-report handler: %s",
                context.message_receipt.sender_did,
            )
            return
        
        data_agreement_negotiation_problem_report = context.message
        

        # Query data agreement instance metadata

        # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Fetch the data agreement instance metadata
        data_agreement_instance_metadata_records = await ada_manager.query_data_agreement_instance_metadata(
            tag_query={
                'data_agreement_id': data_agreement_negotiation_problem_report.data_agreement_id,
            }
        )

        # Check if there is a data agreement instance metadata record
        if not data_agreement_instance_metadata_records:
            self._logger.info(
                "Data agreement not found; Failed to handle negotiation problem report for data agreement: %s",
                data_agreement_negotiation_problem_report.data_agreement_id,
            )
            return
        
        if len(data_agreement_instance_metadata_records) > 1:
            self._logger.info(
                "Duplicate data agreement records found; Failed to handle negotiation problem report for data agreement: %s",
                data_agreement_negotiation_problem_report.data_agreement_id,
            )
            return
        
        data_agreement_instance_metadata_record: StorageRecord = data_agreement_instance_metadata_records[0]

        if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:
            # Check method of use and fetch appropriate exchange record

            # Fetch exchange record (credential exchange if method of use is "data-source")
            tag_filter = {}
            post_filter = {
                "data_agreement_id": data_agreement_negotiation_problem_report.data_agreement_id
            }
            records = await V10CredentialExchange.query(context, tag_filter, post_filter)

            if not records:
                self._logger.info(
                    "Credential exchange record not found; Failed to handle negotiation problem report for data agreement: %s",
                    data_agreement_negotiation_problem_report.data_agreement_id,
                )
                return
            
            if len(records) > 1:
                self._logger.info(
                    "Duplicate credential exchange records found; Failed to handle negotiation problem report for data agreement: %s",
                    data_agreement_negotiation_problem_report.data_agreement_id,
                )
                return
            
            cred_ex_record: V10CredentialExchange = records[0]

            # Update exchange record data agreement status
            cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_PROBLEM_REPORT

            # Add problem report to credential exchange record
            cred_ex_record.data_agreement_problem_report = data_agreement_negotiation_problem_report.serialize()

            # Save the credential exchange record
            await cred_ex_record.save(context)

        if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:
            # Implement data agreement negotiation problem report handler for data using service

            # Check method of use and fetch appropriate exchange record

            # Fetch exchange record (presentation exchange if method of use is "data-using-service")
            tag_filter = {}
            post_filter = {
                "data_agreement_id": data_agreement_negotiation_problem_report.data_agreement_id
            }
            records = await V10PresentationExchange.query(context, tag_filter, post_filter)

            if not records:
                self._logger.info(
                    "Presentation exchange record not found; Failed to handle negotiation problem report for data agreement: %s",
                    data_agreement_negotiation_problem_report.data_agreement_id,
                )
                return
            
            if len(records) > 1:
                self._logger.info(
                    "Duplicate presentation exchange records found; Failed to handle negotiation problem report for data agreement: %s",
                    data_agreement_negotiation_problem_report.data_agreement_id,
                )
                return
            
            pres_ex_record: V10PresentationExchange = records[0]

            # Update exchange record data agreement status
            pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT

            # Add problem report to presentation exchange record
            pres_ex_record.data_agreement_problem_report = data_agreement_negotiation_problem_report.serialize()

            # Save the presentation exchange record
            await pres_ex_record.save(context)


        



