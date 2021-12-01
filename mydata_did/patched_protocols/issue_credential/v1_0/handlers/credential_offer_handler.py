"""Credential offer message handler."""

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ..manager import CredentialManager
from ..messages.credential_offer import CredentialOffer

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

        self._logger.debug("CredentialOfferHandler called with context %s", context)
        assert isinstance(context.message, CredentialOffer)
        self._logger.info(
            "Received credential offer message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential offer")

        credential_manager = CredentialManager(context)

        cred_ex_record = await credential_manager.receive_offer()

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
            await responder.send_reply(credential_request_message)

            trace_event(
                context.settings,
                credential_request_message,
                outcome="CredentialOfferHandler.handle.REQUEST",
                perf_counter=r_time,
            )
