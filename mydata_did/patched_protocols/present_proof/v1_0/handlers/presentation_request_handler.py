"""Presentation request message handler."""

from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)
from .....holder.base import BaseHolder
from .....storage.error import StorageNotFoundError

from ..manager import PresentationManager
from ..messages.presentation_proposal import PresentationProposal
from ..messages.presentation_request import PresentationRequest
from ..models.presentation_exchange import V10PresentationExchange
from ..util.indy import indy_proof_req_preview2indy_requested_creds

from .....utils.tracing import trace_event, get_timer


class PresentationRequestHandler(BaseHandler):
    """Message handler class for Aries#0037 v1.0 presentation requests."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for Aries#0037 v1.0 presentation requests.

        Args:
            context: request context
            responder: responder callback

        """
        r_time = get_timer()

        self._logger.debug("PresentationRequestHandler called with context %s", context)
        assert isinstance(context.message, PresentationRequest)
        self._logger.info(
            "Received presentation request message: %s",
            context.message.serialize(as_string=True),
        )

        if not context.connection_ready:
            raise HandlerException("No connection established for presentation request")

        presentation_manager = PresentationManager(context)

        indy_proof_request = context.message.indy_proof_request(0)

        # Get presentation exchange record (holder initiated via proposal)
        # or create it (verifier sent request first)
        try:
            (
                presentation_exchange_record
            ) = await V10PresentationExchange.retrieve_by_tag_filter(
                context,
                {"thread_id": context.message._thread_id},
                {"connection_id": context.connection_record.connection_id},
            )  # holder initiated via proposal
        except StorageNotFoundError:  # verifier sent this request free of any proposal
            presentation_exchange_record = V10PresentationExchange(
                connection_id=context.connection_record.connection_id,
                thread_id=context.message._thread_id,
                initiator=V10PresentationExchange.INITIATOR_EXTERNAL,
                role=V10PresentationExchange.ROLE_PROVER,
                presentation_request=indy_proof_request,
                auto_present=context.settings.get(
                    "debug.auto_respond_presentation_request"
                ),
                trace=(context.message._trace is not None),
            )

        presentation_exchange_record.presentation_request = indy_proof_request
        presentation_exchange_record = await presentation_manager.receive_request(
            presentation_exchange_record
        )

        r_time = trace_event(
            context.settings,
            context.message,
            outcome="PresentationRequestHandler.handle.END",
            perf_counter=r_time,
        )

        # If auto_present is enabled, respond immediately with presentation
        if presentation_exchange_record.auto_present:
            presentation_preview = None
            if presentation_exchange_record.presentation_proposal_dict:
                exchange_pres_proposal = PresentationProposal.deserialize(
                    presentation_exchange_record.presentation_proposal_dict
                )
                presentation_preview = exchange_pres_proposal.presentation_proposal

            try:
                req_creds = await indy_proof_req_preview2indy_requested_creds(
                    indy_proof_request,
                    presentation_preview,
                    holder=await context.inject(BaseHolder),
                )
            except ValueError as err:
                self._logger.warning(f"{err}")
                return

            (
                presentation_exchange_record,
                presentation_message,
            ) = await presentation_manager.create_presentation(
                presentation_exchange_record=presentation_exchange_record,
                requested_credentials=req_creds,
                comment="auto-presented for proof request nonce={}".format(
                    indy_proof_request["nonce"]
                ),
            )

            await responder.send_reply(presentation_message)

            trace_event(
                context.settings,
                presentation_message,
                outcome="PresentationRequestHandler.handle.PRESENT",
                perf_counter=r_time,
            )
