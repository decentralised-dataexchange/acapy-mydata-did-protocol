"""Credential request message handler."""
import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ..manager import CredentialManager
from ..messages.credential_request import CredentialRequest
from ..models.credential_exchange import V10CredentialExchange

from aries_cloudagent.utils.tracing import trace_event, get_timer
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from .....v1_0.manager import ADAManager, ADAManagerError
from .....v1_0.messages.data_agreement_accept import DataAgreementNegotiationAcceptMessage
from .....v1_0.models.data_agreement_instance_model import DataAgreementInstance, DataAgreementInstanceSchema
from .....v1_0.models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementNegotiationOfferBodySchema
from .....v1_0.utils.jsonld.data_agreement import verify_data_agreement_with_proof_chain
from .....v1_0.utils.did.mydata_did import DIDMyData
from .....v1_0.decorators.data_agreement_context_decorator import DataAgreementContextDecorator
from .....v1_0.messages.problem_report import DataAgreementNegotiationProblemReportReason


class CredentialRequestHandler(BaseHandler):
    """Message handler class for credential requests."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential requests.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug(
            "CredentialRequestHandler called with context %s", context)
        assert isinstance(context.message, CredentialRequest)
        self._logger.info(
            "Received credential request message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException(
                "No connection established for credential request")

        credential_manager = CredentialManager(context)
        cred_ex_record = await credential_manager.receive_request()

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="CredentialRequestHandler.handle.END",
            perf_counter=r_time,
        )

        # Wallet instance from request context
        wallet: IndyWallet = await context.inject(BaseWallet)

        # Initialise ADA manager
        ada_manager = ADAManager(context)

        
        # Process data agreement context decorator
        data_agreement_context_message = None
        try:

            if cred_ex_record.data_agreement and cred_ex_record.data_agreement_status == V10CredentialExchange.DATA_AGREEMENT_OFFER:
                # If data agreement is present and it is in offer state, then check if the request message contains the 
                # data agreement context decorator. If it does, then process it.

                data_agreement_context_message: DataAgreementNegotiationAcceptMessage = await ada_manager.process_data_agreement_context_decorator(
                    decorator_set=context.message._decorators
                )

                if not data_agreement_context_message:

                    # Send problem report
                    problem_report = await ada_manager.construct_data_agreement_negotiation_problem_report_message(
                        connection_record=context.connection_record,
                        data_agreement_id=cred_ex_record.data_agreement_id,
                        problem_code=DataAgreementNegotiationProblemReportReason.DATA_AGREEMENT_CONTEXT_INVALID.value,
                        explain="Data agreement context decorator not found in credential request message"
                    )

                    await ada_manager.send_data_agreement_negotiation_problem_report_message(
                        connection_record=context.connection_record,
                        data_agreement_negotiation_problem_report_message=problem_report
                    )

                    cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_PROBLEM_REPORT
                    cred_ex_record.data_agreement_problem_report = problem_report.serialize()
                    await cred_ex_record.save(context)


                    raise HandlerException(
                        "Data agreement context decorator not found in request message")

                if isinstance(data_agreement_context_message, DataAgreementNegotiationAcceptMessage):

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
                            data_agreement_id=cred_ex_record.data_agreement_id,
                            problem_code=DataAgreementNegotiationProblemReportReason.SIGNATURE_VERIFICATION_FAILED.value,
                            explain="Data agreement accept signature verification failed"
                        )

                        await ada_manager.send_data_agreement_negotiation_problem_report_message(
                            connection_record=context.connection_record,
                            data_agreement_negotiation_problem_report_message=problem_report
                        )

                        cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_PROBLEM_REPORT
                        cred_ex_record.data_agreement_problem_report = problem_report.serialize()
                        await cred_ex_record.save(context)

                        raise HandlerException(
                            "Data agreement accept signature verification failed"
                        )

                    # Update credential exchange record with data agreement metadata
                    cred_ex_record.data_agreement = data_agreement_with_proof_chain.serialize()
                    cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_ACCEPT

                    await cred_ex_record.save(context)

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
                data_agreement_id=cred_ex_record.data_agreement_id,
                problem_code=None,
                explain=str(err)
            )

            await ada_manager.send_data_agreement_negotiation_problem_report_message(
                connection_record=context.connection_record,
                data_agreement_negotiation_problem_report_message=problem_report
            )

            cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_PROBLEM_REPORT
            cred_ex_record.data_agreement_problem_report = problem_report.serialize()
            await cred_ex_record.save(context)

            raise HandlerException(
                f"Error processing data agreement context decorator: {err}")

        # If auto_issue is enabled, respond immediately
        if cred_ex_record.auto_issue:
            if (
                cred_ex_record.credential_proposal_dict
                and "credential_proposal" in cred_ex_record.credential_proposal_dict
            ):
                (
                    cred_ex_record,
                    credential_issue_message,
                ) = await credential_manager.issue_credential(
                    cred_ex_record=cred_ex_record, comment=context.message.comment
                )

                await responder.send_reply(credential_issue_message)

                trace_event(
                    context.settings,
                    credential_issue_message,
                    outcome="CredentialRequestHandler.issue.END",
                    perf_counter=r_time,
                )
            else:
                self._logger.warning(
                    "Operation set for auto-issue but credential exchange record "
                    f"{cred_ex_record.credential_exchange_id} "
                    "has no attribute values"
                )
