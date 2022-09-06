"""Presentation message handler."""
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from aries_cloudagent.utils.tracing import trace_event, get_timer
from mydata_did.patched_protocols.present_proof.v1_0.models.presentation_exchange import (
    V10PresentationExchange
)
from dexa_sdk.managers.ada_manager import V2ADAManager
from ..manager import PresentationManager
from ..messages.presentation import Presentation


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

        presentation_exchange_record: V10PresentationExchange = \
            await presentation_manager.receive_presentation()

        # Initialise ADA manager
        manager = V2ADAManager(context)

        # Process the decorator for data agreement accept message if available.
        await manager.process_decorator_with_da_accept_message(
            context.message._decorators,
            presentation_exchange_record,
            context.connection_record
        )

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
