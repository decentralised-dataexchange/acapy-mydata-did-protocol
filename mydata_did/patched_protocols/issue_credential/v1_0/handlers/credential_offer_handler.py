"""Credential offer message handler."""
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from ..manager import CredentialManager
from ..messages.credential_offer import CredentialOffer
from .....v1_0.decorators.data_agreement_context_decorator import DataAgreementContextDecorator
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

        # Initialise ADA manager
        manager = V2ADAManager(context)

        # Process data agreement context decorator if present.
        # Create data agreement instance from da offer.
        instance_record = await manager.process_decorator_with_da_offer_message(
            context.message._decorators,
            cred_ex_record,
            context.connection_record
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

            # Build data agreement negotiation accept message
            accept_message = \
                await manager.build_data_agreement_negotiation_accept_by_instance_id(
                    instance_record.instance_id,
                    context.connection_record
                )

            # Update credential request message with data agreement context decorator
            credential_request_message._decorators["data-agreement-context"] = \
                DataAgreementContextDecorator(
                message_type="protocol",
                message=accept_message.serialize()
            )

            await responder.send_reply(credential_request_message)

            trace_event(
                context.settings,
                credential_request_message,
                outcome="CredentialOfferHandler.handle.REQUEST",
                perf_counter=r_time,
            )
