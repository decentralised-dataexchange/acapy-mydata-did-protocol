"""Credential request message handler."""
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)

from ..manager import CredentialManager
from ..messages.credential_request import CredentialRequest

from aries_cloudagent.utils.tracing import trace_event, get_timer
from dexa_sdk.managers.ada_manager import V2ADAManager


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

        # Initialise ADA manager
        manager = V2ADAManager(context)

        # Process the decorator for data agreement accept message if available.
        await manager.process_decorator_with_da_accept_message(
            context.message._decorators,
            cred_ex_record,
            context.connection_record
        )

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
