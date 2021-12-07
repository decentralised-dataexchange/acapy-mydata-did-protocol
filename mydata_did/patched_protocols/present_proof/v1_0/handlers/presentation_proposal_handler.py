"""Presentation proposal message handler."""

from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ..manager import PresentationManager
from ..messages.presentation_proposal import PresentationProposal

from .....utils.tracing import trace_event, get_timer


class PresentationProposalHandler(BaseHandler):
    """Message handler class for presentation proposals."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for presentation proposals.

        Args:
            context: proposal context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug(
            "PresentationProposalHandler called with context %s", context
        )
        assert isinstance(context.message, PresentationProposal)
        self._logger.info(
            "Received presentation proposal message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException(
                "No connection established for presentation proposal"
            )

        presentation_manager = PresentationManager(context)
        presentation_exchange_record = await presentation_manager.receive_proposal()

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="PresentationProposalHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto_respond_presentation_proposal is set, reply with proof req
        if context.settings.get("debug.auto_respond_presentation_proposal"):
            (
                presentation_exchange_record,
                presentation_request_message,
            ) = await presentation_manager.create_bound_request(
                presentation_exchange_record=presentation_exchange_record,
                comment=context.message.comment,
            )

            await responder.send_reply(presentation_request_message)

            trace_event(
                context.settings,
                presentation_request_message,
                outcome="PresentationProposalHandler.handle.PRESENT",
                perf_counter=r_time,
            )
