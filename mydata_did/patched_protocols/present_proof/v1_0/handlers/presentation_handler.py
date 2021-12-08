"""Presentation message handler."""

import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
    HandlerException
)

from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from mydata_did.patched_protocols.present_proof.v1_0.models.presentation_exchange import V10PresentationExchange

from ..manager import PresentationManager
from ..messages.presentation import Presentation

from aries_cloudagent.utils.tracing import trace_event, get_timer


from .....v1_0.manager import ADAManager, ADAManagerError
from .....v1_0.messages.data_agreement_accept import DataAgreementNegotiationAcceptMessage
from .....v1_0.messages.problem_report import DataAgreementNegotiationProblemReportReason
from .....v1_0.models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementNegotiationOfferBodySchema
from .....v1_0.models.data_agreement_instance_model import DataAgreementInstance
from .....v1_0.utils.did.mydata_did import DIDMyData
from .....v1_0.utils.jsonld.data_agreement import verify_data_agreement_with_proof_chain


class PresentationHandler(BaseHandler):
    """Message handler class for presentations."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for presentations.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("PresentationHandler called with context %s", context)
        assert isinstance(context.message, Presentation)
        self._logger.info(
            "Received presentation message: %s",
            context.message.serialize(as_string=True),
        )

        presentation_manager = PresentationManager(context)

        presentation_exchange_record : V10PresentationExchange = await presentation_manager.receive_presentation()

        # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialise ADA manager
        ada_manager = ADAManager(context)

        # Process data agreement context decorator
        data_agreement_context_message = None
        try:

            if presentation_exchange_record.data_agreement and presentation_exchange_record.data_agreement_status == V10PresentationExchange.DATA_AGREEMENT_OFFER:
                # If data agreement is present and it is in offer state, then check if the request message contains the 
                # data agreement context decorator. If it does, then process it.

                data_agreement_context_message: DataAgreementNegotiationAcceptMessage = await ada_manager.process_data_agreement_context_decorator(
                    decorator_set=context.message._decorators
                )

                if not data_agreement_context_message:

                    # Send problem report
                    problem_report = await ada_manager.construct_data_agreement_negotiation_problem_report_message(
                        connection_record=context.connection_record,
                        data_agreement_id=presentation_exchange_record.data_agreement_id,
                        problem_code=DataAgreementNegotiationProblemReportReason.DATA_AGREEMENT_CONTEXT_INVALID.value,
                        explain="Data agreement context decorator not found in presentation message"
                    )

                    await ada_manager.send_data_agreement_negotiation_problem_report_message(
                        connection_record=context.connection_record,
                        data_agreement_negotiation_problem_report_message=problem_report
                    )

                    presentation_exchange_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
                    presentation_exchange_record.data_agreement_problem_report = problem_report.serialize()
                    await presentation_exchange_record.save(context)


                    raise HandlerException(
                        "Data agreement context decorator not found in presentation message")
                

                if isinstance(data_agreement_context_message, DataAgreementNegotiationAcceptMessage):

                    # Deserialise data agreement
                    data_agreement_offer: DataAgreementNegotiationOfferBody = DataAgreementNegotiationOfferBodySchema().load(
                        presentation_exchange_record.data_agreement
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
                            data_agreement_context_message.body.event
                        ],
                        proof_chain=[
                            data_agreement_offer.proof,
                            data_agreement_context_message.body.proof
                        ],
                        principle_did=data_agreement_offer.principle_did
                    )

                    # Principle MyData DID (Data Subject)
                    principle_did = DIDMyData.from_did(
                        data_agreement_context_message.body.proof.verification_method)

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

                        # Send problem report
                        problem_report = await ada_manager.construct_data_agreement_negotiation_problem_report_message(
                            connection_record=context.connection_record,
                            data_agreement_id=presentation_exchange_record.data_agreement_id,
                            problem_code=DataAgreementNegotiationProblemReportReason.SIGNATURE_VERIFICATION_FAILED.value,
                            explain="Data agreement accept signature verification failed"
                        )

                        await ada_manager.send_data_agreement_negotiation_problem_report_message(
                            connection_record=context.connection_record,
                            data_agreement_negotiation_problem_report_message=problem_report
                        )

                        presentation_exchange_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_PROBLEM_REPORT
                        presentation_exchange_record.data_agreement_problem_report = problem_report.serialize()
                        await presentation_exchange_record.save(context)

                        raise HandlerException(
                            "Data agreement accept signature verification failed"
                        )

                    # Update credential exchange record with data agreement metadata
                    presentation_exchange_record.data_agreement = data_agreement_with_proof_chain.serialize()
                    presentation_exchange_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_ACCEPT

                    await presentation_exchange_record.save(context)

                    self._logger.info(
                        f"Data agreement negotiation accept context message: \n{json.dumps(data_agreement_context_message.serialize(), indent=4)}\n"
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
                f"Error processing data agreement context decorator: {err}")

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="PresentationHandler.handle.END",
            perf_counter=r_time,
        )

        if context.settings.get("debug.auto_verify_presentation"):
            await presentation_manager.verify_presentation(presentation_exchange_record)

            trace_event(
                context.settings,
                presentation_exchange_record,
                outcome="PresentationHandler.handle.VERIFY",
                perf_counter=r_time,
            )
