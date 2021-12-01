"""Credential proposal message handler."""

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ..manager import CredentialManager
from ..messages.credential_proposal import CredentialProposal

from aries_cloudagent.utils.tracing import trace_event, get_timer


class CredentialProposalHandler(BaseHandler):
    """Message handler class for credential proposals."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for credential proposals.

        Args:
            context: proposal context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("CredentialProposalHandler called with context %s", context)
        assert isinstance(context.message, CredentialProposal)
        self._logger.info(
            "Received credential proposal message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for credential proposal")

        credential_manager = CredentialManager(context)
        cred_ex_record = await credential_manager.receive_proposal()

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="CredentialProposalHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto_offer is enabled, respond immediately with offer
        if cred_ex_record.auto_offer:
            (
                cred_ex_record,
                credential_offer_message,
            ) = await credential_manager.create_offer(
                cred_ex_record, comment=context.message.comment
            )

            await responder.send_reply(credential_offer_message)

            trace_event(
                context.settings,
                credential_offer_message,
                outcome="CredentialProposalHandler.handle.OFFER",
                perf_counter=r_time,
            )
