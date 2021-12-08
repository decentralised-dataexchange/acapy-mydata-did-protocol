from aries_cloudagent.messaging.base_handler import BaseHandler, BaseResponder, RequestContext, HandlerException
from aries_cloudagent.storage.record import StorageRecord
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from ..messages.data_agreement_reject import DataAgreementNegotiationRejectMessage
from ..manager import ADAManager
from ..models.data_agreement_negotiation_reject_model import DataAgreementNegotiationRejectBody
from ..models.exchange_records.data_agreement_record import DataAgreementV1Record
from ..models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementNegotiationOfferBodySchema
from ..models.data_agreement_instance_model import DataAgreementInstance
from ..utils.did.mydata_did import DIDMyData
from ..utils.jsonld.data_agreement import verify_data_agreement_with_proof_chain

from ...patched_protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange
)

from ...patched_protocols.present_proof.v1_0.models.presentation_exchange import (
    V10PresentationExchange
)

import json


class DataAgreementNegotiationRejectMessageHandler(BaseHandler):
    """Handler for data-agreement-negotiation/1.0/reject message."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler logic for data-agreement-negotiation/1.0/reject message."""

        # Assert that the message is of the correct type
        assert isinstance(context.message, DataAgreementNegotiationRejectMessage)

        self._logger.info(
            "Received data-agreement-negotiation/1.0/reject message: \n%s",
            json.dumps(context.message.serialize(), indent=4)
        )

        # Check if connection is ready
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping data-agreement-negotiation/1.0/reject handler: %s",
                context.message_receipt.sender_did,
            )
            return
        
        data_agreement_negotiation_reject_message = context.message
        data_agreement_negotiation_reject_message_body : DataAgreementNegotiationRejectBody = data_agreement_negotiation_reject_message.body

        # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Fetch the data agreement instance metadata
        data_agreement_instance_metadata_records = await ada_manager.query_data_agreement_instance_metadata(
            tag_query={
                'data_agreement_id': data_agreement_negotiation_reject_message_body.data_agreement_id,
            }
        )

        # Check if there is a data agreement instance metadata record
        if not data_agreement_instance_metadata_records:
            self._logger.info(
                "Data agreement not found; Failed to handle data agreement reject message for data agreement: %s",
                data_agreement_negotiation_reject_message_body.data_agreement_id,
            )
            return
        
        if len(data_agreement_instance_metadata_records) > 1:
            self._logger.info(
                "Duplicate data agreement records found; Failed to handle data agreement reject message for data agreement: %s",
                data_agreement_negotiation_reject_message_body.data_agreement_id,
            )
            return
        
        data_agreement_instance_metadata_record: StorageRecord = data_agreement_instance_metadata_records[0]

        # Identify the method of use

        if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:
            
            # Fetch exchante record (credential exchange if method of use is "data-source")
            tag_filter = {}
            post_filter = {
                "data_agreement_id": data_agreement_negotiation_reject_message_body.data_agreement_id
            }
            records = await V10CredentialExchange.query(context, tag_filter, post_filter)

            if not records:
                self._logger.info(
                    "Credential exchange record not found; Failed to handle data agreement reject message for data agreement: %s",
                    data_agreement_negotiation_reject_message_body.data_agreement_id,
                )
                return
            
            if len(records) > 1:
                self._logger.info(
                    "Duplicate credential exchange records found; Failed to handle data agreement reject message for data agreement: %s",
                    data_agreement_negotiation_reject_message_body.data_agreement_id,
                )
                return
            
            cred_ex_record: V10CredentialExchange = records[0]

            # Check if the credential exchange record is in the "offer_sent" state
            if cred_ex_record.state != V10CredentialExchange.STATE_OFFER_SENT:
                self._logger.info(
                    "Credential exchange record not in offer sent state; Failed to handle data agreement reject message for data agreement: %s",
                    data_agreement_negotiation_reject_message_body.data_agreement_id,
                )
                return

            # Reconstruct the data agreement with the reject event and proof

            # Deserialise data agreement
            data_agreement_offer: DataAgreementNegotiationOfferBody = DataAgreementNegotiationOfferBodySchema().load(
                cred_ex_record.data_agreement
            )

            # Construct data agreement with proof chain
            data_agreement_with_proof_chain = DataAgreementInstance(
                context=data_agreement_offer.context,
                data_agreement_id=data_agreement_offer.data_agreement_id,
                data_agreement_version=data_agreement_offer.data_agreement_version,
                data_agreement_template_id=data_agreement_offer.data_agreement_template_id,
                data_agreement_template_version=data_agreement_offer.data_agreement_template_version,
                pii_controller_name=data_agreement_offer.pii_controller_name,
                pii_controller_url=data_agreement_offer.pii_controller_url,
                usage_purpose=data_agreement_offer.usage_purpose,
                usage_purpose_description=data_agreement_offer.usage_purpose_description,
                legal_basis=data_agreement_offer.legal_basis,
                method_of_use=data_agreement_offer.method_of_use,
                data_policy=data_agreement_offer.data_policy,
                personal_data=data_agreement_offer.personal_data,
                dpia=data_agreement_offer.dpia,
                event=[
                    data_agreement_offer.event[0],
                    data_agreement_negotiation_reject_message_body.event
                ],
                proof_chain=[
                    data_agreement_offer.proof,
                    data_agreement_negotiation_reject_message_body.proof
                ],
                principle_did=data_agreement_offer.principle_did
            )

            # Principle MyData DID (Data Subject)
            principle_did = DIDMyData.from_did(
                data_agreement_negotiation_reject_message_body.proof.verification_method)

            # Controler MyData DID (Data Controller - Organisation)
            controller_did = DIDMyData.from_did(
                data_agreement_offer.proof.verification_method)

            # Verify signatures on data agreement
            valid = await verify_data_agreement_with_proof_chain(
                data_agreement_with_proof_chain.serialize(),
                [
                    controller_did.public_key_b58,
                    principle_did.public_key_b58
                ],
                wallet
            )

            if not valid:
                self._logger.error(
                    "Data agreement accept verification failed"
                )

                raise HandlerException(
                    "Data agreement accept signature verification failed"
                )

            # Update credential exchange record with data agreement metadata
            cred_ex_record.data_agreement = data_agreement_with_proof_chain.serialize()
            cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_REJECT

            await cred_ex_record.save(context)

        if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:
            # Implement data-agreement-negotiation/1.0/reject message handler for data-using-service method-of-use
            # Fetch exchange record (presentation exchange if method of use is "data-using-service")
            tag_filter = {}
            post_filter = {
                "data_agreement_id": data_agreement_negotiation_reject_message_body.data_agreement_id
            }
            records = await V10PresentationExchange.query(context, tag_filter, post_filter)

            if not records:
                self._logger.info(
                    "Presentation exchange record not found; Failed to handle data agreement reject message for data agreement: %s",
                    data_agreement_negotiation_reject_message_body.data_agreement_id,
                )
                return
            
            if len(records) > 1:
                self._logger.info(
                    "Duplicate presentation exchange records found; Failed to handle data agreement reject message for data agreement: %s",
                    data_agreement_negotiation_reject_message_body.data_agreement_id,
                )
                return
            
            pres_ex_record: V10PresentationExchange = records[0]

            # Check if the presentation exchange record is in the "request_sent" state
            if pres_ex_record.state != V10PresentationExchange.STATE_REQUEST_SENT:
                self._logger.info(
                    "Presentation exchange record not in request sent state; Failed to handle data agreement reject message for data agreement: %s",
                    data_agreement_negotiation_reject_message_body.data_agreement_id,
                )
                return

            # Reconstruct the data agreement with the reject event and proof

            # Deserialise data agreement
            data_agreement_offer: DataAgreementNegotiationOfferBody = DataAgreementNegotiationOfferBodySchema().load(
                pres_ex_record.data_agreement
            )

            # Construct data agreement with proof chain
            data_agreement_with_proof_chain = DataAgreementInstance(
                context=data_agreement_offer.context,
                data_agreement_id=data_agreement_offer.data_agreement_id,
                data_agreement_version=data_agreement_offer.data_agreement_version,
                data_agreement_template_id=data_agreement_offer.data_agreement_template_id,
                data_agreement_template_version=data_agreement_offer.data_agreement_template_version,
                pii_controller_name=data_agreement_offer.pii_controller_name,
                pii_controller_url=data_agreement_offer.pii_controller_url,
                usage_purpose=data_agreement_offer.usage_purpose,
                usage_purpose_description=data_agreement_offer.usage_purpose_description,
                legal_basis=data_agreement_offer.legal_basis,
                method_of_use=data_agreement_offer.method_of_use,
                data_policy=data_agreement_offer.data_policy,
                personal_data=data_agreement_offer.personal_data,
                dpia=data_agreement_offer.dpia,
                event=[
                    data_agreement_offer.event[0],
                    data_agreement_negotiation_reject_message_body.event
                ],
                proof_chain=[
                    data_agreement_offer.proof,
                    data_agreement_negotiation_reject_message_body.proof
                ],
                principle_did=data_agreement_offer.principle_did
            )

            # Principle MyData DID (Data Subject)
            principle_did = DIDMyData.from_did(
                data_agreement_negotiation_reject_message_body.proof.verification_method)

            # Controler MyData DID (Data Controller - Organisation)
            controller_did = DIDMyData.from_did(
                data_agreement_offer.proof.verification_method)

            # Verify signatures on data agreement
            valid = await verify_data_agreement_with_proof_chain(
                data_agreement_with_proof_chain.serialize(),
                [
                    controller_did.public_key_b58,
                    principle_did.public_key_b58
                ],
                wallet
            )

            if not valid:
                self._logger.error(
                    "Data agreement accept verification failed"
                )

                raise HandlerException(
                    "Data agreement accept signature verification failed"
                )

            # Update presentation exchange record with data agreement metadata
            pres_ex_record.data_agreement = data_agreement_with_proof_chain.serialize()
            pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_REJECT

            await pres_ex_record.save(context)
