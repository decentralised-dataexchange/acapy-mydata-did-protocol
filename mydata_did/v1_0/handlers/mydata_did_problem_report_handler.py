from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from mydata_did.v1_0.manager import ADAManager
from mydata_did.v1_0.messages.problem_report import MyDataDIDProblemReportMessage


class MyDataDIDProblemReportHandler(BaseHandler):
    """
    Handles problem report messages for MyData DID protocol.
    """

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic
        """

        # Assert if received message is of type MyDataDIDProblemReportMessage
        assert isinstance(context.message, MyDataDIDProblemReportMessage)

        self._logger.info(
            "Received problem-report message: %s",
            context.message.serialize(as_string=True),
        )

        # Check if connection is ready
        if not context.connection_ready:
            self._logger.info(
                "Connection not active, skipping problem-report handler: %s",
                context.message_receipt.sender_did,
            )
            return

        # Initialize ADA manager
        mgr = ADAManager(context)

        # Process the problem report message for MyData DID protocol
        await mgr.process_mydata_did_problem_report_message(
            context.message, context.message_receipt
        )
