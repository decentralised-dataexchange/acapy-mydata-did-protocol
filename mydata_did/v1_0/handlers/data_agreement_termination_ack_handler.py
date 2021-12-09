"""Presentation ack message handler."""
import json

from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ..messages.data_agreement_terminate_ack import DataAgreementTerminationAck


class DataAgreementTerminationAckHandler(BaseHandler):
    """Message handler class for data agreement terminate acks."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for data agreement terminate acks.

        Args:
            context: request context
            responder: responder callback
        """

        self._logger.debug("DataAgreementTerminationAckHandler called with context %s", context)

        assert isinstance(context.message, DataAgreementTerminationAck)

        self._logger.info(
            "Received data agreement terminate ack message: %s",
            json.dumps(context.message.serialize(), indent=4),
        )
