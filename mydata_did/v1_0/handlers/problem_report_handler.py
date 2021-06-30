"""Problem report handler."""

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)

from ..messages.problem_report import ProblemReport
from ..manager import ADAManager


class ProblemReportHandler(BaseHandler):
    """Message handler class for problem report messages."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for problem report messages.

        Args:
            context: request context
            responder: responder callback
        """
        self._logger.debug(
            "ProblemReportHandler called with context %s", context)
        assert isinstance(context.message, ProblemReport)

        self._logger.info(
            "Received problem-report message: %s",
            context.message.serialize(as_string=True)
        )
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping problem-report handler: %s",
                context.message_receipt.sender_did,
            )
            return

        mgr = ADAManager(context)
        await mgr.process_problem_report_message(context.message, context.message_receipt)
