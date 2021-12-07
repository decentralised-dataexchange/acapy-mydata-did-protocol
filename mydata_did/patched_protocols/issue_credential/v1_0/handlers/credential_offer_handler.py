"""Credential offer message handler."""
import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet

from ..manager import CredentialManager
from ..messages.credential_offer import CredentialOffer
from ..models.credential_exchange import V10CredentialExchange

from .....v1_0.manager import ADAManager, ADAManagerError
from .....v1_0.messages.data_agreement_offer import DataAgreementNegotiationOfferMessage
from .....v1_0.models.diddoc_model import MyDataDIDResponseBody
from .....v1_0.utils.jsonld.data_agreement import verify_data_agreement
from .....v1_0.utils.did.mydata_did import DIDMyData
from .....v1_0.decorators.data_agreement_context_decorator import DataAgreementContextDecorator
from .....v1_0.messages.problem_report import DataAgreementNegotiationProblemReportReason

from aries_cloudagent.utils.tracing import trace_event, get_timer


class CredentialOfferHandler(BaseHandler):
    """Message handler class for credential offers."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential offers.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug(
            "CredentialOfferHandler called with context %s", context)
        assert isinstance(context.message, CredentialOffer)
        self._logger.info(
            "Received credential offer message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException(
                "No connection established for credential offer")

        credential_manager = CredentialManager(context)

        cred_ex_record = await credential_manager.receive_offer()

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

                    cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_PROBLEM_REPORT
                    cred_ex_record.data_agreement_problem_report = problem_report.serialize()
                    await cred_ex_record.save(context)

                    raise HandlerException(
                        "Data agreement offer signature verification failed"
                    )

                # Update credential exchange record with data agreement
                cred_ex_record.data_agreement = data_agreement_context_message.body.serialize()
                cred_ex_record.data_agreement_id = data_agreement_context_message.body.data_agreement_id
                cred_ex_record.data_agreement_template_id = data_agreement_context_message.body.data_agreement_template_id
                cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_OFFER

                await cred_ex_record.save(context)

                # Save data agreement instance metadata
                await ada_manager.store_data_agreement_instance_metadata(
                    data_agreement_id=data_agreement_context_message.body.data_agreement_id,
                    data_agreement_template_id=data_agreement_context_message.body.data_agreement_template_id,
                    data_exchange_record_id=cred_ex_record.credential_exchange_id,
                    method_of_use=data_agreement_context_message.body.method_of_use
                )

                self._logger.info(
                    f"Data agreement offer verified and stored for credential exchange record {cred_ex_record.credential_exchange_id}"
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
                data_agreement_id=data_agreement_context_message.body.data_agreement_id,
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
                "Failed to process data agreement context decorator: %s" % err
            )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="CredentialOfferHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto respond is turned on, automatically reply with credential request
        if context.settings.get("debug.auto_respond_credential_offer"):
            (_, credential_request_message) = await credential_manager.create_request(
                cred_ex_record=cred_ex_record,
                holder_did=context.connection_record.my_did,
            )

            if data_agreement_context_message:
                try:
                    (data_agreement_instance, data_agreement_negotiation_accept_message) = await ada_manager.construct_data_agreement_negotiation_accept_message(
                        data_agreement_negotiation_offer_body=data_agreement_context_message.body,
                        connection_record=context.connection_record,
                    )

                    # Update credential request message with data agreement context decorator
                    credential_request_message._decorators["data-agreement-context"] = DataAgreementContextDecorator(
                        message_type="protocol",
                        message=data_agreement_negotiation_accept_message.serialize()
                    )

                    # Update credential exchange record with data agreement
                    cred_ex_record.data_agreement = data_agreement_instance.serialize()
                    cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_ACCEPT

                    await cred_ex_record.save(context)

                    self._logger.info(
                        f"Data agreement offer accepted and stored for credential exchange record {cred_ex_record.credential_exchange_id}"
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

            await responder.send_reply(credential_request_message)

            trace_event(
                context.settings,
                credential_request_message,
                outcome="CredentialOfferHandler.handle.REQUEST",
                perf_counter=r_time,
            )
