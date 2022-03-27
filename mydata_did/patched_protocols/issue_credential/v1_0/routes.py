"""Credential exchange admin routes."""

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from json.decoder import JSONDecodeError
from marshmallow import fields, validate
import uuid
import math

from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.issuer.base import IssuerError
from aries_cloudagent.ledger.error import LedgerError
from aries_cloudagent.messaging.credential_definitions.util import CRED_DEF_TAGS
from aries_cloudagent.messaging.models.base import LOGGER, BaseModelError, OpenAPISchema
from aries_cloudagent.messaging.valid import (
    INDY_CRED_DEF_ID,
    INDY_CRED_REV_ID,
    INDY_DID,
    INDY_REV_REG_ID,
    INDY_SCHEMA_ID,
    INDY_VERSION,
    NATURAL_NUM,
    UUIDFour,
    UUID4,
)
from aries_cloudagent.storage.error import StorageDuplicateError, StorageError, StorageNotFoundError
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.error import WalletError
from aries_cloudagent.utils.outofband import serialize_outofband
from aries_cloudagent.utils.tracing import trace_event, get_timer, AdminAPIMessageTracingSchema
from aries_cloudagent.wallet.indy import IndyWallet
from aries_cloudagent.wallet.base import BaseWallet

from aries_cloudagent.protocols.problem_report.v1_0 import internal_error
from aries_cloudagent.protocols.problem_report.v1_0.message import ProblemReport

from mydata_did.v1_0.messages.problem_report import DataAgreementNegotiationProblemReportReason

from .manager import CredentialManager, CredentialManagerError
from .message_types import SPEC_URI
from .messages.credential_proposal import CredentialProposal
from .messages.credential_offer import CredentialOfferSchema
from .messages.inner.credential_preview import (
    CredentialPreview,
    CredentialPreviewSchema,
)
from .models.credential_exchange import (
    V10CredentialExchange,
    V10CredentialExchangeSchema,
)

from ....v1_0.decorators.data_agreement_context_decorator import DataAgreementContextDecorator
from ....v1_0.models.exchange_records.data_agreement_record import DataAgreementV1Record
from ....v1_0.models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementNegotiationOfferBodySchema
from ....v1_0.manager import ADAManager, ADAManagerError
from ....v1_0.models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementNegotiationOfferBodySchema
from ....v1_0.models.data_agreement_instance_model import DataAgreementInstance, DataAgreementInstanceSchema
from ....v1_0.utils.did.mydata_did import DIDMyData
from ....v1_0.utils.wallet.key_type import KeyType
from ....v1_0.utils.util import comma_separated_str_to_list, get_slices


PAGINATION_PAGE_SIZE = 10


class V10CredentialExchangeListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for credential exchange list query."""

    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    thread_id = fields.UUID(
        description="Thread identifier",
        required=False,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    role = fields.Str(
        description="Role assigned in credential exchange",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V10CredentialExchange, m)
                for m in vars(V10CredentialExchange)
                if m.startswith("ROLE_")
            ]
        ),
    )
    state = fields.Str(
        description="Credential exchange state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V10CredentialExchange, m)
                for m in vars(V10CredentialExchange)
                if m.startswith("STATE_")
            ]
        ),
    )

    # Data Agreement identifier
    data_agreement_id = fields.Str(
        required=False,
        description="Data agreement identifier",
        example=UUIDFour.EXAMPLE,
    )

    # Data Agreement template identifier
    data_agreement_template_id = fields.Str(
        required=False,
        description="Data agreement template identifier",
        example=UUIDFour.EXAMPLE,
    )

    # Response fields
    include_fields = fields.Str(
        required=False,
        description="Comma separated fields to be included in the response.",
        example="connection_id,state,presentation_exchange_id",
    )

    page = fields.Int(
        required=False,
        description="Page number",
        example=1,
    )

    page_size = fields.Int(
        required=False,
        description="Page size",
        example=10,
    )


class V10CredentialExchangeListResultSchema(OpenAPISchema):
    """Result schema for Aries#0036 v1.0 credential exchange query."""

    results = fields.List(
        fields.Nested(V10CredentialExchangeSchema),
        description="Aries#0036 v1.0 credential exchange records",
    )


class V10CredentialStoreRequestSchema(OpenAPISchema):
    """Request schema for sending a credential store admin message."""

    credential_id = fields.Str(required=False)


class V10CredentialCreateSchema(AdminAPIMessageTracingSchema):
    """Base class for request schema for sending credential proposal admin message."""

    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=False,
        **INDY_CRED_DEF_ID,
    )
    schema_id = fields.Str(
        description="Schema identifier", required=False, **INDY_SCHEMA_ID
    )
    schema_issuer_did = fields.Str(
        description="Schema issuer DID", required=False, **INDY_DID
    )
    schema_name = fields.Str(
        description="Schema name", required=False, example="preferences"
    )
    schema_version = fields.Str(
        description="Schema version", required=False, **INDY_VERSION
    )
    issuer_did = fields.Str(
        description="Credential issuer DID", required=False, **INDY_DID
    )
    auto_remove = fields.Bool(
        description=(
            "Whether to remove the credential exchange record on completion "
            "(overrides --preserve-exchange-records configuration setting)"
        ),
        required=False,
    )
    comment = fields.Str(
        description="Human-readable comment", required=False, allow_none=True
    )
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )
    credential_proposal = fields.Nested(CredentialPreviewSchema, required=True)


class V10CredentialProposalRequestSchemaBase(AdminAPIMessageTracingSchema):
    """Base class for request schema for sending credential proposal admin message."""

    connection_id = fields.UUID(
        description="Connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=False,
        **INDY_CRED_DEF_ID,
    )
    schema_id = fields.Str(
        description="Schema identifier", required=False, **INDY_SCHEMA_ID
    )
    schema_issuer_did = fields.Str(
        description="Schema issuer DID", required=False, **INDY_DID
    )
    schema_name = fields.Str(
        description="Schema name", required=False, example="preferences"
    )
    schema_version = fields.Str(
        description="Schema version", required=False, **INDY_VERSION
    )
    issuer_did = fields.Str(
        description="Credential issuer DID", required=False, **INDY_DID
    )
    auto_remove = fields.Bool(
        description=(
            "Whether to remove the credential exchange record on completion "
            "(overrides --preserve-exchange-records configuration setting)"
        ),
        required=False,
    )
    comment = fields.Str(
        description="Human-readable comment", required=False, allow_none=True
    )
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )


class V10CredentialProposalRequestOptSchema(V10CredentialProposalRequestSchemaBase):
    """Request schema for sending credential proposal on optional proposal preview."""

    credential_proposal = fields.Nested(
        CredentialPreviewSchema, required=False)


class V10CredentialProposalRequestMandSchema(V10CredentialProposalRequestSchemaBase):
    """Request schema for sending credential proposal on mandatory proposal preview."""

    credential_proposal = fields.Nested(CredentialPreviewSchema, required=True)


class V10CredentialOfferRequestSchema(AdminAPIMessageTracingSchema):
    """Request schema for sending credential offer admin message."""

    connection_id = fields.UUID(
        description="Connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    cred_def_id = fields.Str(
        description="Credential definition identifier",
        required=True,
        **INDY_CRED_DEF_ID,
    )
    auto_issue = fields.Bool(
        description=(
            "Whether to respond automatically to credential requests, creating "
            "and issuing requested credentials"
        ),
        required=False,
    )
    auto_remove = fields.Bool(
        description=(
            "Whether to remove the credential exchange record on completion "
            "(overrides --preserve-exchange-records configuration setting)"
        ),
        required=False,
        default=True,
    )
    comment = fields.Str(
        description="Human-readable comment", required=False, allow_none=True
    )
    credential_preview = fields.Nested(CredentialPreviewSchema, required=True)
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )

    # Data agreement identifier
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=False, example=UUIDFour.EXAMPLE
    )


class V10CredentialIssueRequestSchema(OpenAPISchema):
    """Request schema for sending credential issue admin message."""

    comment = fields.Str(
        description="Human-readable comment", required=False, allow_none=True
    )


class V10CredentialProblemReportRequestSchema(OpenAPISchema):
    """Request schema for sending problem report."""

    explain_ltxt = fields.Str(required=True)


class V10PublishRevocationsSchema(OpenAPISchema):
    """Request and result schema for revocation publication API call."""

    rrid2crid = fields.Dict(
        required=False,
        # marshmallow 3.0 ignores
        keys=fields.Str(example=INDY_REV_REG_ID["example"]),
        values=fields.List(
            fields.Str(
                description="Credential revocation identifier", **INDY_CRED_REV_ID
            )
        ),
        description="Credential revocation ids by revocation registry id",
    )


class V10ClearPendingRevocationsRequestSchema(OpenAPISchema):
    """Request schema for clear pending revocations API call."""

    purge = fields.Dict(
        required=False,
        # marshmallow 3.0 ignores
        keys=fields.Str(example=INDY_REV_REG_ID["example"]),
        values=fields.List(
            fields.Str(
                description="Credential revocation identifier", **INDY_CRED_REV_ID
            )
        ),
        description=(
            "Credential revocation ids by revocation registry id: omit for all, "
            "specify null or empty list for all pending per revocation registry"
        ),
    )


class RevokeQueryStringSchema(OpenAPISchema):
    """Parameters and validators for revocation request."""

    rev_reg_id = fields.Str(
        description="Revocation registry identifier",
        required=True,
        **INDY_REV_REG_ID,
    )
    cred_rev_id = fields.Int(
        description="Credential revocation identifier",
        required=True,
        **NATURAL_NUM,
    )
    publish = fields.Boolean(
        description=(
            "(True) publish revocation to ledger immediately, or "
            "(False) mark it pending (default value)"
        ),
        required=False,
    )


class CredIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential id."""

    credential_id = fields.Str(
        description="Credential identifier", required=True, example=UUIDFour.EXAMPLE
    )


class CredExIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking credential exchange id."""

    cred_ex_id = fields.Str(
        description="Credential exchange identifier", required=True, **UUID4
    )


class CredentialExchangeSendBoundOfferRequestSchema(AdminAPIMessageTracingSchema):
    """Request schema for sending bound offer."""

    # Data agreement identifier
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=False
    )


class DataAgreementBoundCredentialOfferMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking data agreement bound credential offer id."""

    connection_id = fields.UUID(
        description="Connection identifier",
        required=True,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )

    # Data agreement identifier
    data_agreement_id = fields.Str(
        required=True,
        description="The unique identifier for the data agreement.",
        example=UUIDFour.EXAMPLE
    )


class SendDataAgreementNegotiationProblemReportRequestSchema(OpenAPISchema):
    """Request schema for sending problem report."""

    explain = fields.Str(description="Describe the problem", required=True,
                         example="Data agreement context decorator not found in the didcomm message.")
    problem_code = fields.Str(description="Problem code", required=True,
                              example=DataAgreementNegotiationProblemReportReason.DATA_AGREEMENT_CONTEXT_INVALID.value)


@docs(tags=["issue-credential"], summary="Fetch all credential exchange records")
@querystring_schema(V10CredentialExchangeListQueryStringSchema)
@response_schema(V10CredentialExchangeListResultSchema(), 200)
async def credential_exchange_list(request: web.BaseRequest):
    """
    Request handler for searching connection records.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context = request.app["request_context"]
    tag_filter = {}
    if "thread_id" in request.query and request.query["thread_id"] != "":
        tag_filter["thread_id"] = request.query["thread_id"]
    post_filter = {
        k: request.query[k]
        for k in ("connection_id", "role", "state", "data_agreement_id", "data_agreement_template_id")
        if request.query.get(k, "") != ""
    }

    # Pagination parameters
    pagination = {
        "totalCount": 0,
        "page": 0,
        "pageSize": PAGINATION_PAGE_SIZE,
        "totalPages": 0,
    }

    try:

        records = await V10CredentialExchange.query(context, tag_filter, post_filter)

        # Page size from request.
        page_size = int(request.query.get("page_size", PAGINATION_PAGE_SIZE))
        pagination["pageSize"] = page_size

        # Total number of records
        pagination["totalCount"] = len(records)

        # Total number of pages.
        pagination["totalPages"] = math.ceil(
            pagination["totalCount"] / pagination["pageSize"])

        # Fields to be included in the response.
        include_fields = request.query.get("include_fields")
        include_fields = comma_separated_str_to_list(
            include_fields) if include_fields else None

        # Serialise presentation exchange records and customize it based on include_fields.
        results = ADAManager.serialize_credential_exchange_records(
            records, True, include_fields)

        # Pagination parameters
        page = request.query.get("page")

        if page:
            page = int(page)
            pagination["page"] = page

            lower, upper = get_slices(page, pagination["pageSize"])

            results = results[lower:upper]

    except (StorageError, BaseModelError, ValueError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(
        {
            "results": results,
            "pagination": pagination if page else {},
        }
    )


@docs(tags=["issue-credential"], summary="Fetch a single credential exchange record")
@match_info_schema(CredExIdMatchInfoSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_retrieve(request: web.BaseRequest):
    """
    Request handler for fetching single connection record.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    credential_exchange_id = request.match_info["cred_ex_id"]
    cred_ex_record = None
    try:
        cred_ex_record = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
        result = cred_ex_record.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError) as err:
        await internal_error(err, web.HTTPBadRequest, cred_ex_record, outbound_handler)

    return web.json_response(result)


@docs(
    tags=["issue-credential"],
    summary="Send holder a credential, automating entire flow",
)
@request_schema(V10CredentialCreateSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_create(request: web.BaseRequest):
    """
    Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection. This can be used in conjunction with
    the `oob` protocols to bind messages to an out of band message.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]

    body = await request.json()

    comment = body.get("comment")
    preview_spec = body.get("credential_proposal")
    if not preview_spec:
        raise web.HTTPBadRequest(reason="credential_proposal must be provided")
    auto_remove = body.get("auto_remove")
    trace_msg = body.get("trace")

    try:
        preview = CredentialPreview.deserialize(preview_spec)

        credential_proposal = CredentialProposal(
            comment=comment,
            credential_proposal=preview,
            **{t: body.get(t) for t in CRED_DEF_TAGS if body.get(t)},
        )
        credential_proposal.assign_trace_decorator(
            context.settings,
            trace_msg,
        )

        trace_event(
            context.settings,
            credential_proposal,
            outcome="credential_exchange_create.START",
        )

        credential_manager = CredentialManager(context)

        (
            credential_exchange_record,
            credential_offer_message,
        ) = await credential_manager.prepare_send(
            None,
            credential_proposal=credential_proposal,
            auto_remove=auto_remove,
        )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    trace_event(
        context.settings,
        credential_offer_message,
        outcome="credential_exchange_create.END",
        perf_counter=r_time,
    )

    return web.json_response(credential_exchange_record.serialize())


@docs(
    tags=["issue-credential"],
    summary="Send holder a credential, automating entire flow",
)
@request_schema(V10CredentialProposalRequestMandSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_send(request: web.BaseRequest):
    """
    Request handler for sending credential from issuer to holder from attr values.

    If both issuer and holder are configured for automatic responses, the operation
    ultimately results in credential issue; otherwise, the result waits on the first
    response not automated; the credential exchange record retains state regardless.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()

    comment = body.get("comment")
    connection_id = body.get("connection_id")
    preview_spec = body.get("credential_proposal")
    if not preview_spec:
        raise web.HTTPBadRequest(reason="credential_proposal must be provided")
    auto_remove = body.get("auto_remove")
    trace_msg = body.get("trace")

    connection_record = None
    cred_ex_record = None
    try:
        preview = CredentialPreview.deserialize(preview_spec)
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        credential_proposal = CredentialProposal(
            comment=comment,
            credential_proposal=preview,
            **{t: body.get(t) for t in CRED_DEF_TAGS if body.get(t)},
        )
        credential_proposal.assign_trace_decorator(
            context.settings,
            trace_msg,
        )

        trace_event(
            context.settings,
            credential_proposal,
            outcome="credential_exchange_send.START",
        )

        credential_manager = CredentialManager(context)
        (
            cred_ex_record,
            credential_offer_message,
        ) = await credential_manager.prepare_send(
            connection_id,
            credential_proposal=credential_proposal,
            auto_remove=auto_remove,
        )
        result = cred_ex_record.serialize()
    except (StorageError, BaseModelError, CredentialManagerError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(
        credential_offer_message, connection_id=cred_ex_record.connection_id
    )

    trace_event(
        context.settings,
        credential_offer_message,
        outcome="credential_exchange_send.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["issue-credential"], summary="Send issuer a credential proposal")
@request_schema(V10CredentialProposalRequestOptSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_send_proposal(request: web.BaseRequest):
    """
    Request handler for sending credential proposal.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()

    connection_id = body.get("connection_id")
    comment = body.get("comment")
    preview_spec = body.get("credential_proposal")
    auto_remove = body.get("auto_remove")
    trace_msg = body.get("trace")

    connection_record = None
    cred_ex_record = None
    try:
        preview = CredentialPreview.deserialize(
            preview_spec) if preview_spec else None
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        credential_manager = CredentialManager(context)
        cred_ex_record = await credential_manager.create_proposal(
            connection_id,
            comment=comment,
            credential_preview=preview,
            auto_remove=auto_remove,
            trace=trace_msg,
            **{t: body.get(t) for t in CRED_DEF_TAGS if body.get(t)},
        )

        credential_proposal = CredentialProposal.deserialize(
            cred_ex_record.credential_proposal_dict
        )
        result = cred_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(
        credential_proposal,
        connection_id=connection_id,
    )

    trace_event(
        context.settings,
        credential_proposal,
        outcome="credential_exchange_send_proposal.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


async def _create_free_offer(
    context,
    cred_def_id: str,
    connection_id: str = None,
    auto_issue: bool = False,
    auto_remove: bool = False,
    preview_spec: dict = None,
    comment: str = None,
    trace_msg: bool = None,
):
    """Create a credential offer and related exchange record."""

    credential_preview = CredentialPreview.deserialize(preview_spec)
    credential_proposal = CredentialProposal(
        comment=comment,
        credential_proposal=credential_preview,
        cred_def_id=cred_def_id,
    )
    credential_proposal.assign_trace_decorator(
        context.settings,
        trace_msg,
    )
    credential_proposal_dict = credential_proposal.serialize()

    cred_ex_record = V10CredentialExchange(
        connection_id=connection_id,
        initiator=V10CredentialExchange.INITIATOR_SELF,
        credential_definition_id=cred_def_id,
        credential_proposal_dict=credential_proposal_dict,
        auto_issue=auto_issue,
        auto_remove=auto_remove,
        trace=trace_msg,
    )

    credential_manager = CredentialManager(context)

    (
        cred_ex_record,
        credential_offer_message,
    ) = await credential_manager.create_offer(cred_ex_record, comment=comment)

    return (cred_ex_record, credential_offer_message)


@docs(
    tags=["issue-credential"],
    summary="Create a credential offer, independent of any proposal",
)
@request_schema(V10CredentialOfferRequestSchema())
@response_schema(CredentialOfferSchema(), 200)
async def credential_exchange_create_free_offer(request: web.BaseRequest):
    """
    Request handler for creating free credential offer.

    Unlike with `send-offer`, this credential exchange is not tied to a specific
    connection. It must be dispatched out-of-band by the controller.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()

    cred_def_id = body.get("cred_def_id")
    if not cred_def_id:
        raise web.HTTPBadRequest(reason="cred_def_id is required")

    auto_issue = body.get(
        "auto_issue", context.settings.get(
            "debug.auto_respond_credential_request")
    )
    auto_remove = body.get("auto_remove")
    comment = body.get("comment")
    preview_spec = body.get("credential_preview")
    if not preview_spec:
        raise web.HTTPBadRequest(reason=("Missing credential_preview"))

    connection_id = body.get("connection_id")
    trace_msg = body.get("trace")

    wallet: BaseWallet = await context.inject(BaseWallet)
    if connection_id:
        try:
            connection_record = await ConnectionRecord.retrieve_by_id(
                context, connection_id
            )
            conn_did = await wallet.get_local_did(connection_record.my_did)
        except (WalletError, StorageError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err
    else:
        conn_did = await wallet.get_public_did()
        if not conn_did:
            raise web.HTTPBadRequest(
                reason=f"Wallet '{wallet.name}' has no public DID")
        connection_id = None

    did_info = await wallet.get_public_did()
    endpoint = did_info.metadata.get(
        "endpoint", context.settings.get("default_endpoint")
    )
    if not endpoint:
        raise web.HTTPBadRequest(
            reason="An endpoint for the public DID is required")

    cred_ex_record = None
    try:
        (cred_ex_record, credential_offer_message,) = await _create_free_offer(
            context,
            cred_def_id,
            connection_id,
            auto_issue,
            auto_remove,
            preview_spec,
            comment,
            trace_msg,
        )

        trace_event(
            context.settings,
            credential_offer_message,
            outcome="credential_exchange_create_free_offer.END",
            perf_counter=r_time,
        )

        oob_url = serialize_outofband(
            credential_offer_message, conn_did, endpoint)
        result = cred_ex_record.serialize()
    except (BaseModelError, CredentialManagerError, LedgerError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    response = {"record": result, "oob_url": oob_url}
    return web.json_response(response)


@docs(
    tags=["issue-credential"],
    summary="Send holder a credential offer, independent of any proposal",
)
@request_schema(V10CredentialOfferRequestSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_send_free_offer(request: web.BaseRequest):
    """
    Request handler for sending free credential offer.

    An issuer initiates a such a credential offer, free from any
    holder-initiated corresponding credential proposal with preview.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """

    print("Patched route for sending credential offers.")

    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()

    connection_id = body.get("connection_id")
    cred_def_id = body.get("cred_def_id")
    if not cred_def_id:
        raise web.HTTPBadRequest(reason="cred_def_id is required")

    auto_issue = body.get(
        "auto_issue", context.settings.get(
            "debug.auto_respond_credential_request")
    )

    auto_remove = body.get("auto_remove")
    comment = body.get("comment")
    preview_spec = body.get("credential_preview")
    if not preview_spec:
        raise web.HTTPBadRequest(reason=("Missing credential_preview"))
    trace_msg = body.get("trace")

    cred_ex_record = None
    connection_record = None
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        (cred_ex_record, credential_offer_message,) = await _create_free_offer(
            context,
            cred_def_id,
            connection_id,
            auto_issue,
            auto_remove,
            preview_spec,
            comment,
            trace_msg,
        )
        result = cred_ex_record.serialize()
    except (
        StorageNotFoundError,
        BaseModelError,
        CredentialManagerError,
        LedgerError,
    ) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    # Add data agreement context decorator if data agreement identifier is present
    if "data_agreement_id" in body:

        # Fetch data agreement record
        data_agreement_id = body.get("data_agreement_id")

        # Tag filter
        tag_filter = {
            "data_agreement_id": data_agreement_id,
            "publish_flag": "true",
            "delete_flag": "false",
        }

        try:

            # Query for the old data agreement record by id
            old_data_agreement_record: DataAgreementV1Record = await DataAgreementV1Record.retrieve_by_tag_filter(
                context,
                tag_filter=tag_filter
            )

            # Initialize ADA manager
            ada_manager = ADAManager(context)

            # Construct data agreement offer message.
            data_agreement_offer_message = await ada_manager.construct_data_agreement_offer_message(
                connection_record=connection_record,
                data_agreement_template_record=old_data_agreement_record,
            )

            # Add data agreement context decorator
            credential_offer_message._decorators["data-agreement-context"] = DataAgreementContextDecorator(
                message_type="protocol",
                message=data_agreement_offer_message.serialize()
            )

            cred_ex_record.credential_offer_dict = credential_offer_message.serialize()
            cred_ex_record.data_agreement = data_agreement_offer_message.body.serialize()
            cred_ex_record.data_agreement_id = data_agreement_offer_message.body.data_agreement_id
            cred_ex_record.data_agreement_template_id = data_agreement_offer_message.body.data_agreement_template_id
            cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_OFFER
            await cred_ex_record.save(context)

            # Save data agreement instance metadata
            await ada_manager.store_data_agreement_instance_metadata(
                data_agreement_id=data_agreement_offer_message.body.data_agreement_id,
                data_agreement_template_id=data_agreement_offer_message.body.data_agreement_template_id,
                data_exchange_record_id=cred_ex_record.credential_exchange_id,
                method_of_use=data_agreement_offer_message.body.method_of_use
            )

            result = cred_ex_record.serialize()

        except (StorageNotFoundError, StorageDuplicateError) as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

    await outbound_handler(credential_offer_message, connection_id=connection_id)

    trace_event(
        context.settings,
        credential_offer_message,
        outcome="credential_exchange_send_free_offer.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential"],
    summary="Send holder a credential offer in reference to a proposal with preview",
)
@match_info_schema(CredExIdMatchInfoSchema())
@request_schema(CredentialExchangeSendBoundOfferRequestSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_send_bound_offer(request: web.BaseRequest):
    """
    Request handler for sending bound credential offer.

    A holder initiates this sequence with a credential proposal; this message
    responds with an offer bound to the proposal.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    # Request body
    body = await request.json()

    # Data agreement identifier from request body
    data_agreement_id = body.get("data_agreement_id", None)

    credential_exchange_id = request.match_info["cred_ex_id"]
    try:
        cred_ex_record = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    connection_record = None
    connection_id = cred_ex_record.connection_id
    try:
        if cred_ex_record.state != (
            V10CredentialExchange.STATE_PROPOSAL_RECEIVED
        ):  # check state here: manager call creates free offers too
            raise CredentialManagerError(
                f"Credential exchange {cred_ex_record.credential_exchange_id} "
                f"in {cred_ex_record.state} state "
                f"(must be {V10CredentialExchange.STATE_PROPOSAL_RECEIVED})"
            )

        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        credential_manager = CredentialManager(context)
        (
            cred_ex_record,
            credential_offer_message,
        ) = await credential_manager.create_offer(cred_ex_record, comment=None)

        if data_agreement_id:

            # Tag filter
            tag_filter = {
                "data_agreement_id": data_agreement_id,
                "publish_flag": "true",
                "delete_flag": "false",
            }

            try:

                # Query for the old data agreement record by id
                old_data_agreement_record: DataAgreementV1Record = await DataAgreementV1Record.retrieve_by_tag_filter(
                    context,
                    tag_filter=tag_filter
                )

                # Initialize ADA manager
                ada_manager = ADAManager(context)

                # Construct data agreement offer message.
                data_agreement_offer_message = await ada_manager.construct_data_agreement_offer_message(
                    connection_record=connection_record,
                    data_agreement_template_record=old_data_agreement_record,
                )

                # Add data agreement context decorator
                credential_offer_message._decorators["data-agreement-context"] = DataAgreementContextDecorator(
                    message_type="protocol",
                    message=data_agreement_offer_message.serialize()
                )

                cred_ex_record.credential_offer_dict = credential_offer_message.serialize()
                cred_ex_record.data_agreement = data_agreement_offer_message.body.serialize()
                cred_ex_record.data_agreement_id = data_agreement_offer_message.body.data_agreement_id
                cred_ex_record.data_agreement_template_id = data_agreement_offer_message.body.data_agreement_template_id
                cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_OFFER
                await cred_ex_record.save(context)

                # Save data agreement instance metadata
                await ada_manager.store_data_agreement_instance_metadata(
                    data_agreement_id=data_agreement_offer_message.body.data_agreement_id,
                    data_agreement_template_id=data_agreement_offer_message.body.data_agreement_template_id,
                    data_exchange_record_id=cred_ex_record.credential_exchange_id,
                    method_of_use=data_agreement_offer_message.body.method_of_use
                )

            except (StorageNotFoundError, StorageDuplicateError, ADAManagerError) as err:
                raise web.HTTPBadRequest(reason=err.roll_up) from err

        result = cred_ex_record.serialize()
    except (StorageError, BaseModelError, CredentialManagerError, LedgerError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(credential_offer_message, connection_id=connection_id)

    trace_event(
        context.settings,
        credential_offer_message,
        outcome="credential_exchange_send_bound_offer.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["issue-credential"], summary="Send issuer a credential request")
@match_info_schema(CredExIdMatchInfoSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_send_request(request: web.BaseRequest):
    """
    Request handler for sending credential request.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    credential_exchange_id = request.match_info["cred_ex_id"]
    try:
        cred_ex_record = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    connection_id = cred_ex_record.connection_id

    connection_record = None
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        credential_manager = CredentialManager(context)
        (
            cred_ex_record,
            credential_request_message,
        ) = await credential_manager.create_request(
            cred_ex_record, connection_record.my_did
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        try:
            if cred_ex_record.data_agreement:

                if cred_ex_record.data_agreement_status == V10CredentialExchange.DATA_AGREEMENT_OFFER:
                    # Check if data agreement is present in credential exchange record and it is in offer state
                    # If so, then accept the data agreement and attach it to the credential request

                    # Load data agreement offer
                    data_agreement_negotiation_offer_body: DataAgreementNegotiationOfferBody = DataAgreementNegotiationOfferBodySchema().load(
                        cred_ex_record.data_agreement
                    )

                    (data_agreement_instance, data_agreement_negotiation_accept_message) = await ada_manager.construct_data_agreement_negotiation_accept_message(
                        data_agreement_negotiation_offer_body=data_agreement_negotiation_offer_body,
                        connection_record=connection_record,
                    )

                    # Update credential request message with data agreement context decorator
                    credential_request_message._decorators["data-agreement-context"] = DataAgreementContextDecorator(
                        message_type="protocol",
                        message=data_agreement_negotiation_accept_message.serialize()
                    )

                    # Update credential exchange record with data agreement
                    cred_ex_record.data_agreement = data_agreement_instance.serialize()
                    cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_ACCEPT

                    await cred_ex_record.save(context)
                else:
                    raise web.HTTPBadRequest(
                        reason="Data agreement is not in offer state.")

        except ADAManagerError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

        result = cred_ex_record.serialize()
    except (StorageError, CredentialManagerError, BaseModelError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(credential_request_message, connection_id=connection_id)

    trace_event(
        context.settings,
        credential_request_message,
        outcome="credential_exchange_send_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["issue-credential"], summary="Send holder a credential")
@match_info_schema(CredExIdMatchInfoSchema())
@request_schema(V10CredentialIssueRequestSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_issue(request: web.BaseRequest):
    """
    Request handler for sending credential.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()
    comment = body.get("comment")

    credential_exchange_id = request.match_info["cred_ex_id"]
    try:
        cred_ex_record = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    connection_id = cred_ex_record.connection_id

    connection_record = None
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        credential_manager = CredentialManager(context)
        (
            cred_ex_record,
            credential_issue_message,
        ) = await credential_manager.issue_credential(cred_ex_record, comment=comment)

        result = cred_ex_record.serialize()
    except (BaseModelError, CredentialManagerError, IssuerError, StorageError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(credential_issue_message, connection_id=connection_id)

    trace_event(
        context.settings,
        credential_issue_message,
        outcome="credential_exchange_issue.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["issue-credential"], summary="Store a received credential")
@match_info_schema(CredExIdMatchInfoSchema())
@request_schema(V10CredentialStoreRequestSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def credential_exchange_store(request: web.BaseRequest):
    """
    Request handler for storing credential.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    try:
        body = await request.json() or {}
        credential_id = body.get("credential_id")
    except JSONDecodeError:
        credential_id = None

    credential_exchange_id = request.match_info["cred_ex_id"]
    try:
        cred_ex_record = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    connection_record = None
    connection_id = cred_ex_record.connection_id
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        credential_manager = CredentialManager(context)
        (
            cred_ex_record,
            credential_stored_message,
        ) = await credential_manager.store_credential(cred_ex_record, credential_id)

        result = cred_ex_record.serialize()
    except (StorageError, CredentialManagerError, BaseModelError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            cred_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(credential_stored_message, connection_id=connection_id)

    trace_event(
        context.settings,
        credential_stored_message,
        outcome="credential_exchange_store.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["issue-credential"], summary="Remove an existing credential exchange record"
)
@match_info_schema(CredExIdMatchInfoSchema())
async def credential_exchange_remove(request: web.BaseRequest):
    """
    Request handler for removing a credential exchange record.

    Args:
        request: aiohttp request object

    """
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    credential_exchange_id = request.match_info["cred_ex_id"]
    cred_ex_record = None
    try:
        cred_ex_record = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )

        await cred_ex_record.delete_record(context)

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Delete data agreement instance metadata
        await ada_manager.delete_data_agreement_instance_metadata(
            tag_query={
                "data_exchange_record_id": credential_exchange_id
            }
        )

    except StorageNotFoundError as err:
        await internal_error(err, web.HTTPNotFound, cred_ex_record, outbound_handler)
    except StorageError as err:
        await internal_error(err, web.HTTPBadRequest, cred_ex_record, outbound_handler)

    return web.json_response({})


@docs(
    tags=["issue-credential"], summary="Send a problem report for credential exchange"
)
@match_info_schema(CredExIdMatchInfoSchema())
@request_schema(V10CredentialProblemReportRequestSchema())
async def credential_exchange_problem_report(request: web.BaseRequest):
    """
    Request handler for sending problem report.

    Args:
        request: aiohttp request object

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    credential_exchange_id = request.match_info["cred_ex_id"]
    body = await request.json()

    try:
        cred_ex_record = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    error_result = ProblemReport(explain_ltxt=body["explain_ltxt"])
    error_result.assign_thread_id(cred_ex_record.thread_id)

    await outbound_handler(error_result, connection_id=cred_ex_record.connection_id)

    trace_event(
        context.settings,
        error_result,
        outcome="credential_exchange_problem_report.END",
        perf_counter=r_time,
    )

    return web.json_response({})


@docs(
    tags=["issue-credential"], summary="Send data agreement reject message for a credential offer"
)
@match_info_schema(CredExIdMatchInfoSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def send_data_agreement_reject_message_for_credential_offer(request: web.BaseRequest):
    """
    Request handler for sending data agreement reject message for credential offer

    Args:
        request: aiohttp request object

    """

    # Initialize request context
    context = request.app["request_context"]

    # Initialize outbound handler
    outbound_handler = request.app["outbound_message_router"]

    # Path parameters
    credential_exchange_id = request.match_info["cred_ex_id"]

    cred_ex_record = None
    try:
        # Fetch credential exchange record
        cred_ex_record: V10CredentialExchange = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    if not cred_ex_record.state == V10CredentialExchange.STATE_OFFER_RECEIVED:
        raise web.HTTPBadRequest(
            reason=f"Credential exchange must be in {V10CredentialExchange.STATE_OFFER_RECEIVED} state in order to reject the offer.")

    if not cred_ex_record.data_agreement:
        raise web.HTTPBadRequest(reason=f"Data agreement is not available.")

    if not cred_ex_record.data_agreement_status == V10CredentialExchange.DATA_AGREEMENT_OFFER:
        raise web.HTTPBadRequest(
            reason=f"Data agreement must be in offer state to reject it."
        )

    # Send data agreement reject message

    data_agreement_negotiation_offer_body: DataAgreementNegotiationOfferBody = DataAgreementNegotiationOfferBodySchema().load(
        cred_ex_record.data_agreement
    )

    # Initialize ADA manager
    ada_manager = ADAManager(context)

    connection_record = None
    connection_id = cred_ex_record.connection_id
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        (data_agreement_instance, data_agreement_negotiation_reject_message) = await ada_manager.construct_data_agreement_negotiation_reject_message(
            data_agreement_negotiation_offer_body=data_agreement_negotiation_offer_body,
            connection_record=connection_record,
        )

        # Update credential exchange record with data agreement
        cred_ex_record.data_agreement = data_agreement_instance.serialize()
        cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_REJECT

        await cred_ex_record.save(context)

        await outbound_handler(data_agreement_negotiation_reject_message, connection_id=cred_ex_record.connection_id)

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(cred_ex_record.serialize())


@docs(
    tags=["issue-credential"], summary="Send data agreement negotiation problem report message"
)
@match_info_schema(CredExIdMatchInfoSchema())
@request_schema(SendDataAgreementNegotiationProblemReportRequestSchema())
async def send_data_agreement_negotiation_problem_report(request: web.BaseRequest):
    """
    Request handler for sending data agreement negotiation problem report message

    Args:
        request: aiohttp request object
    """

    # Initialize request context
    context = request.app["request_context"]

    # Initialize outbound handler
    outbound_handler = request.app["outbound_message_router"]

    # Path parameters
    credential_exchange_id = request.match_info["cred_ex_id"]

    # Request payload
    body = await request.json()
    explain = body.get("explain", "")
    problem_code = body.get("problem_code", "")

    cred_ex_record = None
    try:
        # Fetch credential exchange record
        cred_ex_record: V10CredentialExchange = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    if not cred_ex_record.data_agreement:
        raise web.HTTPBadRequest(reason=f"Data agreement is not available.")

    # Initialize ADA manager
    ada_manager = ADAManager(context)

    connection_record = None
    connection_id = cred_ex_record.connection_id
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        data_agreement_negotiation_problem_report = await ada_manager.construct_data_agreement_negotiation_problem_report_message(
            connection_record=connection_record,
            data_agreement_id=cred_ex_record.data_agreement_id,
            problem_code=problem_code,
            explain=explain,
        )

        await ada_manager.send_data_agreement_negotiation_problem_report_message(
            connection_record=connection_record,
            data_agreement_negotiation_problem_report_message=data_agreement_negotiation_problem_report,
        )

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({})


@docs(
    tags=["issue-credential"], summary="Send data agreement termination message."
)
@match_info_schema(CredExIdMatchInfoSchema())
@response_schema(V10CredentialExchangeSchema(), 200)
async def send_data_agreement_termination_message(request: web.BaseRequest):
    """
    Request handler for sending data agreement termination message.

    Args:
        request: aiohttp request object

    """

    # Initialize request context
    context = request.app["request_context"]

    # Initialize outbound handler
    outbound_handler = request.app["outbound_message_router"]

    # Path parameters
    credential_exchange_id = request.match_info["cred_ex_id"]

    cred_ex_record = None
    try:
        # Fetch credential exchange record
        cred_ex_record: V10CredentialExchange = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    if not cred_ex_record.data_agreement:
        raise web.HTTPBadRequest(reason=f"Data agreement is not available.")

    if not cred_ex_record.data_agreement_status == V10CredentialExchange.DATA_AGREEMENT_ACCEPT:
        raise web.HTTPBadRequest(
            reason=f"Data agreement must be in accept state to terminate it."
        )

    # Send data agreement terminate message

    data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
        cred_ex_record.data_agreement
    )

    # Initialize ADA manager
    ada_manager = ADAManager(context)

    connection_record = None
    connection_id = cred_ex_record.connection_id
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        # Fetch wallet from context
        wallet: IndyWallet = await context.inject(BaseWallet)

        pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
        principle_did = DIDMyData.from_public_key_b58(
            pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

        if data_agreement_instance.principle_did != principle_did.did:
            raise web.HTTPBadRequest(
                reason=f"Only the principle can terminate the data agreement."
            )

        (data_agreement_instance, data_agreement_terminate_message) = await ada_manager.construct_data_agreement_termination_terminate_message(
            data_agreement_instance=data_agreement_instance,
            connection_record=connection_record,
        )

        # Update credential exchange record with data agreement
        cred_ex_record.data_agreement = data_agreement_instance.serialize()
        cred_ex_record.data_agreement_status = V10CredentialExchange.DATA_AGREEMENT_TERMINATE

        await cred_ex_record.save(context)

        await outbound_handler(data_agreement_terminate_message, connection_id=cred_ex_record.connection_id)

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(cred_ex_record.serialize())


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get(
                "/issue-credential/records", credential_exchange_list, allow_head=False
            ),
            web.get(
                "/issue-credential/records/{cred_ex_id}",
                credential_exchange_retrieve,
                allow_head=False,
            ),
            web.post("/issue-credential/create", credential_exchange_create),
            web.post("/issue-credential/send", credential_exchange_send),
            web.post(
                "/issue-credential/send-proposal", credential_exchange_send_proposal
            ),
            web.post(
                "/issue-credential/send-offer", credential_exchange_send_free_offer
            ),
            web.post(
                "/issue-credential/records/{cred_ex_id}/send-offer",
                credential_exchange_send_bound_offer,
            ),
            web.post(
                "/issue-credential/records/{cred_ex_id}/send-request",
                credential_exchange_send_request,
            ),
            web.post(
                "/issue-credential/records/{cred_ex_id}/issue",
                credential_exchange_issue,
            ),
            web.post(
                "/issue-credential/records/{cred_ex_id}/store",
                credential_exchange_store,
            ),
            web.post(
                "/issue-credential/records/{cred_ex_id}/problem-report",
                credential_exchange_problem_report,
            ),
            web.delete(
                "/issue-credential/records/{cred_ex_id}",
                credential_exchange_remove,
            ),
            web.post(
                "/issue-credential/records/{cred_ex_id}/data-agreement-negotiation/reject",
                send_data_agreement_reject_message_for_credential_offer,
            ),

            web.post(
                "/issue-credential/records/{cred_ex_id}/data-agreement-negotiation/problem-report",
                send_data_agreement_negotiation_problem_report,
            ),

            web.post(
                "/issue-credential/records/{cred_ex_id}/data-agreement-termination/terminate",
                send_data_agreement_termination_message,
            ),

        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "issue-credential",
            "description": "Credential issue, revocation",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
