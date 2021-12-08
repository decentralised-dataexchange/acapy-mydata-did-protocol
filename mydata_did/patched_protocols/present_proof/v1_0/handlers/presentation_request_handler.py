"""Presentation request message handler."""

import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)
from aries_cloudagent.holder.base import BaseHolder
from aries_cloudagent.storage.error import StorageNotFoundError
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from ..manager import PresentationManager
from ..messages.presentation_proposal import PresentationProposal
from ..messages.presentation_request import PresentationRequest
from ..models.presentation_exchange import V10PresentationExchange
from ..util.indy import indy_proof_req_preview2indy_requested_creds

from aries_cloudagent.utils.tracing import trace_event, get_timer


from .....v1_0.manager import ADAManager, ADAManagerError
from .....v1_0.decorators.data_agreement_context_decorator import DataAgreementContextDecorator
from .....v1_0.messages.data_agreement_offer import DataAgreementNegotiationOfferMessage
from .....v1_0.messages.problem_report import DataAgreementNegotiationProblemReportReason
from .....v1_0.utils.did.mydata_did import DIDMyData
from .....v1_0.utils.jsonld.data_agreement import verify_data_agreement


class PresentationRequestHandler(BaseHandler):
    """Message handler class for Aries#0037 v1.0 presentation requests."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for Aries#0037 v1.0 presentation requests.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("PresentationRequestHandler called with context %s", context)
        assert isinstance(context.message, PresentationRequest)
        self._logger.info(
            "Received presentation request message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for presentation request")

        presentation_manager = PresentationManager(context)

        indy_proof_request = context.message.indy_proof_request(0)

        # Get presentation exchange record (holder initiated via proposal)
        # or create it (verifier sent request first)
        try:
            (
                presentation_exchange_record
            ) = await V10PresentationExchange.retrieve_by_tag_filter(
                context,
                {"thread_id": context.message._thread_id},
                {"connection_id": context.connection_record.connection_id},
            )  # holder initiated via proposal
        except StorageNotFoundError:  # verifier sent this request free of any proposal
            presentation_exchange_record = V10PresentationExchange(
                connection_id=context.connection_record.connection_id,
                thread_id=context.message._thread_id,
                initiator=V10PresentationExchange.INITIATOR_EXTERNAL,
                role=V10PresentationExchange.ROLE_PROVER,
                presentation_request=indy_proof_request,
                auto_present=context.settings.get(
                    "debug.auto_respond_presentation_request"
                ),
                trace=(context.message._trace is not None),
            )

        presentation_exchange_record.presentation_request = indy_proof_request
        presentation_exchange_record = await presentation_manager.receive_request(
            presentation_exchange_record
        )

         # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialise ADA manager
        ada_manager = ADAManager(context)

        # Process data agreement context decorator
        data_agreement_context_message = None
        try:
            data_agreement_context_message: DataAgreementNegotiationOfferMessage = await ada_manager.process_data_agreement_context_decorator(
                decorator_set=context.message._decorators
            )

            if isinstance(data_agreement_context_message, DataAgreementNegotiationOfferMessage):


                # Resolve controller DID (Organisation DID) from MyData DID registry
                controller_mydata_did = DIDMyData.from_did(
                    data_agreement_context_message.body.proof.verification_method)

                await ada_manager.resolve_remote_mydata_did(mydata_did=controller_mydata_did.did)

                # Verify signatures on data agreement offer
                valid = await verify_data_agreement(
                    data_agreement_context_message.body.serialize(),
                    controller_mydata_did.public_key_b58,
                    wallet
                )

                if not valid:
                    self._logger.error(
                        "Data agreement offer verification failed"
                    )

                    # Send problem report
                    problem_report = await ada_manager.construct_data_agreement_negotiation_problem_report_message(
                        connection_record=context.connection_record,
                        data_agreement_id=data_agreement_context_message.body.data_agreement_id,
                        problem_code=DataAgreementNegotiationProblemReportReason.SIGNATURE_VERIFICATION_FAILED.value,
                        explain="Data agreement offer verification failed"
                    )

                    await ada_manager.send_data_agreement_negotiation_problem_report_message(
                        connection_record=context.connection_record,
                        data_agreement_negotiation_problem_report_message=problem_report
                    )

                    presentation_exchange_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
                    presentation_exchange_record.data_agreement_problem_report = problem_report.serialize()
                    await presentation_exchange_record.save(context)

                    raise HandlerException(
                        "Data agreement offer signature verification failed"
                    )
                

                # Update presentation exchange record with data agreement
                presentation_exchange_record.data_agreement = data_agreement_context_message.body.serialize()
                presentation_exchange_record.data_agreement_id = data_agreement_context_message.body.data_agreement_id
                presentation_exchange_record.data_agreement_template_id = data_agreement_context_message.body.data_agreement_template_id
                presentation_exchange_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_OFFER

                await presentation_exchange_record.save(context)

                # Save data agreement instance metadata
                await ada_manager.store_data_agreement_instance_metadata(
                    data_agreement_id=data_agreement_context_message.body.data_agreement_id,
                    data_agreement_template_id=data_agreement_context_message.body.data_agreement_template_id,
                    data_exchange_record_id=presentation_exchange_record.presentation_exchange_id,
                    method_of_use=data_agreement_context_message.body.method_of_use
                )

                self._logger.info(
                    f"Data agreement offer verified and stored for presentation exchange record {presentation_exchange_record.presentation_exchange_id}"
                )

                self._logger.info(
                    f"Received data agreement offer context message: \n{json.dumps(data_agreement_context_message.serialize(), indent=4)}\n"
                )



        except ADAManagerError as err:
            self._logger.error(
                "Failed to process data agreement context decorator: %s", err
            )

            # Send problem report
            problem_report = await ada_manager.construct_data_agreement_negotiation_problem_report_message(
                connection_record=context.connection_record,
                data_agreement_id=presentation_exchange_record.data_agreement_id,
                problem_code=None,
                explain=str(err)
            )

            await ada_manager.send_data_agreement_negotiation_problem_report_message(
                connection_record=context.connection_record,
                data_agreement_negotiation_problem_report_message=problem_report
            )

            presentation_exchange_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
            presentation_exchange_record.data_agreement_problem_report = problem_report.serialize()
            await presentation_exchange_record.save(context)

            raise HandlerException(
                "Failed to process data agreement context decorator: %s" % err
            )



        r_time = trace_event(
            context.settings,
            context.message,
            outcome="PresentationRequestHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto_present is enabled, respond immediately with presentation
        if presentation_exchange_record.auto_present:
            presentation_preview = None
            if presentation_exchange_record.presentation_proposal_dict:
                exchange_pres_proposal = PresentationProposal.deserialize(
                    presentation_exchange_record.presentation_proposal_dict
                )
                presentation_preview = exchange_pres_proposal.presentation_proposal

            try:
                req_creds = await indy_proof_req_preview2indy_requested_creds(
                    indy_proof_request,
                    presentation_preview,
                    holder=await context.inject(BaseHolder),
                )
            except ValueError as err:
                self._logger.warning(f"{err}")
                return

            (
                presentation_exchange_record,
                presentation_message,
            ) = await presentation_manager.create_presentation(
                presentation_exchange_record=presentation_exchange_record,
                requested_credentials=req_creds,
                comment="auto-presented for proof request nonce={}".format(
                    indy_proof_request["nonce"]
                ),
            )

            if data_agreement_context_message:

                # Attach presentation message with data agreement context decorator
                # Data agreement context decorator will carry data agreement accept repsonse.


                try:
                    (data_agreement_instance, data_agreement_negotiation_accept_message) = await ada_manager.construct_data_agreement_negotiation_accept_message(
                        data_agreement_negotiation_offer_body=data_agreement_context_message.body,
                        connection_record=context.connection_record,
                    )

                    # Update presentation message with data agreement context decorator
                    presentation_message._decorators["data-agreement-context"] = DataAgreementContextDecorator(
                        message_type="protocol",
                        message=data_agreement_negotiation_accept_message.serialize()
                    )

                    # Update presentation exchange record with data agreement
                    presentation_exchange_record.data_agreement = data_agreement_instance.serialize()
                    presentation_exchange_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_ACCEPT

                    await presentation_exchange_record.save(context)

                    self._logger.info(
                        f"Data agreement offer accepted and stored for presentation exchange record {presentation_exchange_record.presentation_exchange_id}"
                    )

                    self._logger.info(
                        f"Data agreement negotiation accept context message: \n{json.dumps(data_agreement_negotiation_accept_message.serialize(), indent=4)}\n"
                    )

                except ADAManagerError as err:
                    self._logger.error(
                        "Failed to construct data agreement negotiation accept message: %s", err
                    )

                    raise HandlerException(
                        "Failed to construct data agreement negotiation accept message: %s" % err
                    )

            await responder.send_reply(presentation_message)

            trace_event(
                context.settings,
                presentation_message,
                outcome="PresentationRequestHandler.handle.PRESENT",
                perf_counter=r_time,
            )
