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
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.issuer.base import IssuerError
from aries_cloudagent.ledger.error import LedgerError
from aries_cloudagent.messaging.credential_definitions.util import CRED_DEF_TAGS
from aries_cloudagent.messaging.models.base import BaseModelError, OpenAPISchema
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
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.error import WalletError
from aries_cloudagent.utils.outofband import serialize_outofband
from aries_cloudagent.utils.tracing import trace_event, get_timer, AdminAPIMessageTracingSchema

from aries_cloudagent.protocols.problem_report.v1_0 import internal_error
from aries_cloudagent.protocols.problem_report.v1_0.message import ProblemReport
from mydata_did.v1_0.messages.problem_report import DataAgreementNegotiationProblemReportReason
from dexa_sdk.managers.ada_manager import V2ADAManager
from dexa_sdk.agreements.da.v1_0.records.da_template_record import DataAgreementTemplateRecord
from dexa_sdk.utils import paginate_records, clean_and_get_field_from_dict
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

    # Data Agreement template identifier
    template_id = fields.Str(required=False)

    # Page
    page = fields.Int(required=False)

    # Page size
    page_size = fields.Int(required=False)


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
        required=False,
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
    credential_preview = fields.Nested(CredentialPreviewSchema, required=False)
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )

    # Data agreement template identifier
    template_id = fields.Str(
        description="Data agreement template identifier", required=False, example=UUIDFour.EXAMPLE
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
        for k in ("connection_id", "role", "state", "template_id")
        if request.query.get(k, "") != ""
    }

    page = clean_and_get_field_from_dict(request.query, "page")
    page = int(page) if page is not None else page
    page_size = clean_and_get_field_from_dict(request.query, "page_size")
    page_size = int(page_size) if page_size is not None else page_size

    try:
        records = await V10CredentialExchange.query(context, tag_filter, post_filter)

        # Pagination result.
        pagination_result = paginate_records(
            records,
            page if page else 1,
            page_size if page_size else 10
        )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(pagination_result._asdict())


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
    template_id = body.get("template_id")

    # Fetch data agreement template record
    template_record: DataAgreementTemplateRecord = None
    if template_id:
        template_record: DataAgreementTemplateRecord = \
            await DataAgreementTemplateRecord.latest_published_template_by_id(
                context,
                template_id
            )

        # Validate agreement method of use
        if template_record.method_of_use != DataAgreementTemplateRecord.METHOD_OF_USE_DATA_SOURCE:
            raise web.HTTPBadRequest(
                reason="Data agreement method of use must be data-source."
            )

        # Replace cred def id from template if available.
        cred_def_id = template_record.cred_def_id if template_record.cred_def_id else cred_def_id

    # Check if either cred def id or data agreement id is present.
    if not cred_def_id and not template_id:
        raise web.HTTPBadRequest(
            reason="Either cred def id or data agreement template id is required."
        )

    # Data agreement model
    da_model = template_record.data_agreement_model

    # Third party data sharing or not.
    third_party_data_sharing = da_model.data_policy.third_party_data_sharing

    auto_issue = body.get(
        "auto_issue", context.settings.get(
            "debug.auto_respond_credential_request")
    )

    auto_remove = body.get("auto_remove")
    comment = body.get("comment")

    # If not third party data sharing,
    # then use credential preview from request body
    if not third_party_data_sharing:
        preview_spec = body.get("credential_preview")
        if not preview_spec:
            raise web.HTTPBadRequest(reason=("Missing credential_preview"))
    else:
        # If third party data sharing,
        # then construct the credential dynamically from personal data.
        # Values are empty strings.
        preview_spec_attrs = []
        for pd in da_model.personal_data:
            preview_spec_attrs.append({
                "name": pd.attribute_name,
                "value": " "
            })
        preview_spec = {
            "@type": "issue-credential/1.0/credential-preview",
            "attributes": preview_spec_attrs
        }

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

    # Initialise MyData DID Manager
    manager: V2ADAManager = V2ADAManager(context=context)

    # Construct data agreement offer message.
    data_agreement_offer_message = \
        await manager.build_data_agreement_offer_for_credential_exchange(
            template_id=template_id,
            cred_ex_record=cred_ex_record,
            connection_record=connection_record,

        )

    # Add data agreement context decorator
    credential_offer_message._decorators["data-agreement-context"] =\
        DataAgreementContextDecorator(
        message_type="protocol",
        message=data_agreement_offer_message.serialize()
    )

    cred_ex_record.credential_offer_dict = credential_offer_message.serialize()
    cred_ex_record.template_id = template_id
    await cred_ex_record.save(context)

    result = cred_ex_record.serialize()

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
            raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

        credential_manager = CredentialManager(context)
        (
            cred_ex_record,
            credential_offer_message,
        ) = await credential_manager.create_offer(cred_ex_record, comment=None)

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

        # Initialize ADA manager.
        manager = V2ADAManager(context)

        # Create data agreement accept message.
        accept_message = await manager.build_data_agreement_accept_for_data_ex_record(
            connection_record,
            cred_ex_record
        )

        # Update credential request message with data agreement context decorator
        credential_request_message._decorators["data-agreement-context"] = \
            DataAgreementContextDecorator(
            message_type="protocol",
            message=accept_message.serialize()
        )

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
        cred_ex_record: V10CredentialExchange = await V10CredentialExchange.retrieve_by_id(
            context, credential_exchange_id
        )

        await cred_ex_record.delete_record(context)

        # Initialize ADA manager
        manager = V2ADAManager(context)

        # Delete data agreement instance
        await manager.delete_da_instance_by_data_ex_id(cred_ex_record.credential_exchange_id)

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
