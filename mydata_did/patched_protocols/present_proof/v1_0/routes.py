"""Admin routes for presentations."""

import json
import math

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet
from marshmallow import fields, validate, validates_schema
from marshmallow.exceptions import ValidationError

from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.holder.base import BaseHolder, HolderError
from aries_cloudagent.indy.util import generate_pr_nonce
from aries_cloudagent.ledger.error import LedgerError
from aries_cloudagent.messaging.decorators.attach_decorator import AttachDecorator
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.messaging.valid import (
    INDY_CRED_DEF_ID,
    INDY_DID,
    INDY_EXTRA_WQL,
    INDY_PREDICATE,
    INDY_SCHEMA_ID,
    INDY_VERSION,
    INT_EPOCH,
    NATURAL_NUM,
    UUIDFour,
    UUID4,
    WHOLE_NUM,
)
from aries_cloudagent.storage.error import StorageError, StorageNotFoundError
from aries_cloudagent.utils.tracing import trace_event, get_timer, AdminAPIMessageTracingSchema
from aries_cloudagent.wallet.error import WalletNotFoundError

from aries_cloudagent.protocols.problem_report.v1_0 import internal_error

from .manager import PresentationManager
from .message_types import ATTACH_DECO_IDS, PRESENTATION_REQUEST, SPEC_URI
from .messages.inner.presentation_preview import (
    PresentationPreview,
    PresentationPreviewSchema,
)
from .messages.presentation_proposal import PresentationProposal
from .messages.presentation_request import PresentationRequest
from .models.presentation_exchange import (
    V10PresentationExchange,
    V10PresentationExchangeSchema,
)

from ....v1_0.decorators.data_agreement_context_decorator import DataAgreementContextDecorator
from ....v1_0.models.exchange_records.data_agreement_record import DataAgreementV1Record
from ....v1_0.models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementNegotiationOfferBodySchema
from ....v1_0.manager import ADAManager, ADAManagerError
from ....v1_0.models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementNegotiationOfferBodySchema
from ....v1_0.models.data_agreement_instance_model import DataAgreementInstance, DataAgreementInstanceSchema
from ....patched_protocols.issue_credential.v1_0.routes import SendDataAgreementNegotiationProblemReportRequestSchema
from ....v1_0.utils.did.mydata_did import DIDMyData
from ....v1_0.utils.wallet.key_type import KeyType
from ....v1_0.utils.util import comma_separated_str_to_list, get_slices


PAGINATION_PAGE_SIZE = 10


class V10PresentationExchangeListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for presentation exchange list query."""

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
        description="Role assigned in presentation exchange",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V10PresentationExchange, m)
                for m in vars(V10PresentationExchange)
                if m.startswith("ROLE_")
            ]
        ),
    )
    state = fields.Str(
        description="Presentation exchange state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(V10PresentationExchange, m)
                for m in vars(V10PresentationExchange)
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


class V10PresentationExchangeListSchema(OpenAPISchema):
    """Result schema for an Aries RFC 37 v1.0 presentation exchange query."""

    results = fields.List(
        fields.Nested(V10PresentationExchangeSchema()),
        description="Aries RFC 37 v1.0 presentation exchange records",
    )


class V10PresentationProposalRequestSchema(AdminAPIMessageTracingSchema):
    """Request schema for sending a presentation proposal admin message."""

    connection_id = fields.UUID(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )
    comment = fields.Str(
        description="Human-readable comment", required=False, allow_none=True
    )
    presentation_proposal = fields.Nested(
        PresentationPreviewSchema(), required=True)
    auto_present = fields.Boolean(
        description=(
            "Whether to respond automatically to presentation requests, building "
            "and presenting requested proof"
        ),
        required=False,
        default=False,
    )
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )


class DAIndyProofReqPredSpecRestrictionsSchema(OpenAPISchema):
    """Schema for restrictions in attr or pred specifier indy proof request."""

    schema_id = fields.String(
        description="Schema identifier", required=False, **INDY_SCHEMA_ID
    )
    schema_issuer_did = fields.String(
        description="Schema issuer (origin) DID", required=False, **INDY_DID
    )
    schema_name = fields.String(
        example="transcript", description="Schema name", required=False
    )
    schema_version = fields.String(
        description="Schema version", required=False, **INDY_VERSION
    )
    issuer_did = fields.String(
        description="Credential issuer DID", required=False, **INDY_DID
    )
    cred_def_id = fields.String(
        description="Credential definition identifier",
        required=False,
        **INDY_CRED_DEF_ID,
    )


class DAIndyProofReqNonRevokedSchema(OpenAPISchema):
    """Non-revocation times specification in indy proof request."""

    fro = fields.Int(
        description="Earliest epoch of interest for non-revocation proof",
        required=False,
        data_key="from",
        **INT_EPOCH,
    )
    to = fields.Int(
        description="Latest epoch of interest for non-revocation proof",
        required=False,
        **INT_EPOCH,
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """
        Validate schema fields - must have from, to, or both.

        Args:
            data: The data to validate

        Raises:
            ValidationError: if data has neither from nor to

        """
        if not (data.get("from") or data.get("to")):
            raise ValidationError(
                "Non-revocation interval must have at least one end", ("fro",
                                                                       "to")
            )


class DAIndyProofReqAttrSpecSchema(OpenAPISchema):
    """Schema for attribute specification in indy proof request."""

    name = fields.String(
        example="favouriteDrink", description="Attribute name", required=False
    )
    names = fields.List(
        fields.String(example="age"),
        description="Attribute name group",
        required=False,
    )
    restrictions = fields.List(
        fields.Dict(
            keys=fields.Str(
                validate=validate.Regexp(
                    "^schema_id|"
                    "schema_issuer_did|"
                    "schema_name|"
                    "schema_version|"
                    "issuer_did|"
                    "cred_def_id|"
                    "attr::.+::value$"  # indy does not support attr::...::marker here
                ),
                example="cred_def_id",  # marshmallow/apispec v3.0 ignores
            ),
            values=fields.Str(example=INDY_CRED_DEF_ID["example"]),
        ),
        description=(
            "If present, credential must satisfy one of given restrictions: specify "
            "schema_id, schema_issuer_did, schema_name, schema_version, "
            "issuer_did, cred_def_id, and/or attr::<attribute-name>::value "
            "where <attribute-name> represents a credential attribute name"
        ),
        required=False,
    )
    non_revoked = fields.Nested(
        DAIndyProofReqNonRevokedSchema(), required=False)

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """
        Validate schema fields.

        Data must have exactly one of name or names; if names then restrictions are
        mandatory.

        Args:
            data: The data to validate

        Raises:
            ValidationError: if data has both or neither of name and names

        """
        if ("name" in data) == ("names" in data):
            raise ValidationError(
                "Attribute specification must have either name or names but not both"
            )
        restrictions = data.get("restrictions")
        if ("names" in data) and (not restrictions or all(not r for r in restrictions)):
            raise ValidationError(
                "Attribute specification on 'names' must have non-empty restrictions"
            )


class DAIndyProofReqPredSpecSchema(OpenAPISchema):
    """Schema for predicate specification in indy proof request."""

    name = fields.String(
        example="index", description="Attribute name", required=True)
    p_type = fields.String(
        description="Predicate type ('<', '<=', '>=', or '>')",
        required=True,
        **INDY_PREDICATE,
    )
    p_value = fields.Integer(description="Threshold value", required=True)
    restrictions = fields.List(
        fields.Nested(DAIndyProofReqPredSpecRestrictionsSchema()),
        description="If present, credential must satisfy one of given restrictions",
        required=False,
    )
    non_revoked = fields.Nested(
        DAIndyProofReqNonRevokedSchema(), required=False)


class DAIndyProofRequestSchema(OpenAPISchema):
    """Schema for indy proof request."""

    nonce = fields.String(description="Nonce",
                          required=False, example="1234567890")
    name = fields.String(
        description="Proof request name",
        required=False,
        example="Proof request",
        default="Proof request",
    )
    version = fields.String(
        description="Proof request version",
        required=False,
        default="1.0",
        **INDY_VERSION,
    )
    requested_attributes = fields.Dict(
        description=("Requested attribute specifications of proof request"),
        required=True,
        # marshmallow/apispec v3.0 ignores
        keys=fields.Str(example="0_attr_uuid"),
        values=fields.Nested(DAIndyProofReqAttrSpecSchema()),
    )
    requested_predicates = fields.Dict(
        description=("Requested predicate specifications of proof request"),
        required=True,
        # marshmallow/apispec v3.0 ignores
        keys=fields.Str(example="0_age_GE_uuid"),
        values=fields.Nested(DAIndyProofReqPredSpecSchema()),
    )
    non_revoked = fields.Nested(
        DAIndyProofReqNonRevokedSchema(), required=False)


class V10PresentationCreateRequestRequestSchema(AdminAPIMessageTracingSchema):
    """Request schema for creating a proof request free of any connection."""

    proof_request = fields.Nested(DAIndyProofRequestSchema(), required=True)
    comment = fields.Str(required=False, allow_none=True)
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )


class V10PresentationSendRequestRequestSchema(
    V10PresentationCreateRequestRequestSchema
):
    """Request schema for sending a proof request on a connection."""

    connection_id = fields.UUID(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )


class IndyRequestedCredsRequestedAttrSchema(OpenAPISchema):
    """Schema for requested attributes within indy requested credentials structure."""

    cred_id = fields.Str(
        example="3fa85f64-5717-4562-b3fc-2c963f66afa6",
        description=(
            "Wallet credential identifier (typically but not necessarily a UUID)"
        ),
        required=True,
    )
    revealed = fields.Bool(
        description="Whether to reveal attribute in proof", required=True
    )
    timestamp = fields.Int(
        description="Epoch timestamp of interest for non-revocation proof",
        required=False,
        **INT_EPOCH,
    )


class IndyRequestedCredsRequestedPredSchema(OpenAPISchema):
    """Schema for requested predicates within indy requested credentials structure."""

    cred_id = fields.Str(
        description=(
            "Wallet credential identifier (typically but not necessarily a UUID)"
        ),
        example="3fa85f64-5717-4562-b3fc-2c963f66afa6",
        required=True,
    )
    timestamp = fields.Int(
        description="Epoch timestamp of interest for non-revocation proof",
        required=False,
        **INT_EPOCH,
    )


class V10PresentationRequestSchema(AdminAPIMessageTracingSchema):
    """Request schema for sending a presentation."""

    self_attested_attributes = fields.Dict(
        description=("Self-attested attributes to build into proof"),
        required=True,
        # marshmallow/apispec v3.0 ignores
        keys=fields.Str(example="attr_name"),
        values=fields.Str(
            example="self_attested_value",
            description=(
                "Self-attested attribute values to use in requested-credentials "
                "structure for proof construction"
            ),
        ),
    )
    requested_attributes = fields.Dict(
        description=(
            "Nested object mapping proof request attribute referents to "
            "requested-attribute specifiers"
        ),
        required=True,
        # marshmallow/apispec v3.0 ignores
        keys=fields.Str(example="attr_referent"),
        values=fields.Nested(IndyRequestedCredsRequestedAttrSchema()),
    )
    requested_predicates = fields.Dict(
        description=(
            "Nested object mapping proof request predicate referents to "
            "requested-predicate specifiers"
        ),
        required=True,
        # marshmallow/apispec v3.0 ignores
        keys=fields.Str(example="pred_referent"),
        values=fields.Nested(IndyRequestedCredsRequestedPredSchema()),
    )
    trace = fields.Bool(
        description="Whether to trace event (default false)",
        required=False,
        example=False,
    )


class CredentialsFetchQueryStringSchema(OpenAPISchema):
    """Parameters and validators for credentials fetch request query string."""

    referent = fields.Str(
        description="Proof request referents of interest, comma-separated",
        required=False,
        example="1_name_uuid,2_score_uuid",
    )
    start = fields.Int(description="Start index", required=False, **WHOLE_NUM)
    count = fields.Int(
        description="Maximum number to retrieve", required=False, **NATURAL_NUM
    )
    extra_query = fields.Str(
        description="(JSON) object mapping referents to extra WQL queries",
        required=False,
        **INDY_EXTRA_WQL,
    )


class PresExIdMatchInfoSchema(OpenAPISchema):
    """Path parameters and validators for request taking presentation exchange id."""

    pres_ex_id = fields.Str(
        description="Presentation exchange identifier", required=True, **UUID4
    )


class SendPresentationRequestForDataAgreementRequestSchema(OpenAPISchema):
    """Request schema for sending a presentation request for a data agreement."""

    connection_id = fields.UUID(
        description="Connection identifier", required=True, example=UUIDFour.EXAMPLE
    )

    # Data agreement identifier
    data_agreement_id = fields.Str(
        description="Data agreement identifier", required=True, **UUID4
    )


@docs(tags=["present-proof"], summary="Fetch all present-proof exchange records")
@querystring_schema(V10PresentationExchangeListQueryStringSchema)
@response_schema(V10PresentationExchangeListSchema(), 200)
async def presentation_exchange_list(request: web.BaseRequest):
    """
    Request handler for searching presentation exchange records.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange list response

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

        records = await V10PresentationExchange.query(context, tag_filter, post_filter)

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
        results = ADAManager.serialize_presentation_exchange_records(
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


@docs(tags=["present-proof"], summary="Fetch a single presentation exchange record")
@match_info_schema(PresExIdMatchInfoSchema())
@response_schema(V10PresentationExchangeSchema(), 200)
async def presentation_exchange_retrieve(request: web.BaseRequest):
    """
    Request handler for fetching a single presentation exchange record.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange record response

    """
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    presentation_exchange_id = request.match_info["pres_ex_id"]
    pres_ex_record = None
    try:
        pres_ex_record = await V10PresentationExchange.retrieve_by_id(
            context, presentation_exchange_id
        )
        result = pres_ex_record.serialize()
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError) as err:
        await internal_error(err, web.HTTPBadRequest, pres_ex_record, outbound_handler)

    return web.json_response(result)


@docs(
    tags=["present-proof"],
    summary="Fetch credentials for a presentation request from wallet",
)
@match_info_schema(PresExIdMatchInfoSchema())
@querystring_schema(CredentialsFetchQueryStringSchema())
async def presentation_exchange_credentials_list(request: web.BaseRequest):
    """
    Request handler for searching applicable credential records.

    Args:
        request: aiohttp request object

    Returns:
        The credential list response

    """
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    presentation_exchange_id = request.match_info["pres_ex_id"]
    referents = request.query.get("referent")
    presentation_referents = (
        (r.strip() for r in referents.split(",")) if referents else ()
    )

    try:
        pres_ex_record = await V10PresentationExchange.retrieve_by_id(
            context, presentation_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    start = request.query.get("start")
    count = request.query.get("count")

    # url encoded json extra_query
    encoded_extra_query = request.query.get("extra_query") or "{}"
    extra_query = json.loads(encoded_extra_query)

    # defaults
    start = int(start) if isinstance(start, str) else 0
    count = int(count) if isinstance(count, str) else 10

    holder: BaseHolder = await context.inject(BaseHolder)
    try:
        credentials = await holder.get_credentials_for_presentation_request_by_referent(
            pres_ex_record.presentation_request,
            presentation_referents,
            start,
            count,
            extra_query,
        )
    except HolderError as err:
        await internal_error(err, web.HTTPBadRequest, pres_ex_record, outbound_handler)

    pres_ex_record.log_state(
        context,
        "Retrieved presentation credentials",
        {
            "presentation_exchange_id": presentation_exchange_id,
            "referents": presentation_referents,
            "extra_query": extra_query,
            "credentials": credentials,
        },
    )
    return web.json_response(credentials)


@docs(tags=["present-proof"], summary="Sends a presentation proposal")
@request_schema(V10PresentationProposalRequestSchema())
@response_schema(V10PresentationExchangeSchema(), 200)
async def presentation_exchange_send_proposal(request: web.BaseRequest):
    """
    Request handler for sending a presentation proposal.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()

    comment = body.get("comment")
    connection_id = body.get("connection_id")

    # Aries RFC 37 calls it a proposal in the proposal struct but it's of type preview
    presentation_preview = body.get("presentation_proposal")
    connection_record = None
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        presentation_proposal_message = PresentationProposal(
            comment=comment,
            presentation_proposal=PresentationPreview.deserialize(
                presentation_preview),
        )
    except (BaseModelError, StorageError) as err:
        await internal_error(
            err, web.HTTPBadRequest, connection_record, outbound_handler
        )

    if not connection_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    trace_msg = body.get("trace")
    presentation_proposal_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )
    auto_present = body.get(
        "auto_present", context.settings.get(
            "debug.auto_respond_presentation_request")
    )

    presentation_manager = PresentationManager(context)
    pres_ex_record = None
    try:
        pres_ex_record = await presentation_manager.create_exchange_for_proposal(
            connection_id=connection_id,
            presentation_proposal_message=presentation_proposal_message,
            auto_present=auto_present,
        )
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(presentation_proposal_message, connection_id=connection_id)

    trace_event(
        context.settings,
        presentation_proposal_message,
        outcome="presentation_exchange_propose.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["present-proof"],
    summary="""
    Creates a presentation request not bound to any proposal or existing connection
    """,
)
@request_schema(V10PresentationCreateRequestRequestSchema())
@response_schema(V10PresentationExchangeSchema(), 200)
async def presentation_exchange_create_request(request: web.BaseRequest):
    """
    Request handler for creating a free presentation request.

    The presentation request will not be bound to any proposal
    or existing connection.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()

    comment = body.get("comment")
    indy_proof_request = body.get("proof_request")
    if not indy_proof_request.get("nonce"):
        indy_proof_request["nonce"] = await generate_pr_nonce()

    presentation_request_message = PresentationRequest(
        comment=comment,
        request_presentations_attach=[
            AttachDecorator.from_indy_dict(
                indy_dict=indy_proof_request,
                ident=ATTACH_DECO_IDS[PRESENTATION_REQUEST],
            )
        ],
    )
    trace_msg = body.get("trace")
    presentation_request_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )

    presentation_manager = PresentationManager(context)
    pres_ex_record = None
    try:
        (pres_ex_record) = await presentation_manager.create_exchange_for_request(
            connection_id=None,
            presentation_request_message=presentation_request_message,
        )
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        await internal_error(err, web.HTTPBadRequest, pres_ex_record, outbound_handler)

    await outbound_handler(presentation_request_message, connection_id=None)

    trace_event(
        context.settings,
        presentation_request_message,
        outcome="presentation_exchange_create_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["present-proof"],
    summary="Sends a free presentation request not bound to any proposal",
)
@request_schema(V10PresentationSendRequestRequestSchema())
@response_schema(V10PresentationExchangeSchema(), 200)
async def presentation_exchange_send_free_request(request: web.BaseRequest):
    """
    Request handler for sending a presentation request free from any proposal.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    body = await request.json()

    connection_id = body.get("connection_id")
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not connection_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    comment = body.get("comment")
    indy_proof_request = body.get("proof_request")
    if not indy_proof_request.get("nonce"):
        indy_proof_request["nonce"] = await generate_pr_nonce()

    presentation_request_message = PresentationRequest(
        comment=comment,
        request_presentations_attach=[
            AttachDecorator.from_indy_dict(
                indy_dict=indy_proof_request,
                ident=ATTACH_DECO_IDS[PRESENTATION_REQUEST],
            )
        ],
    )
    trace_msg = body.get("trace")
    presentation_request_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )

    presentation_manager = PresentationManager(context)
    pres_ex_record = None
    try:
        (pres_ex_record) = await presentation_manager.create_exchange_for_request(
            connection_id=connection_id,
            presentation_request_message=presentation_request_message,
        )
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or connection_record,
            outbound_handler,
        )

    await outbound_handler(presentation_request_message, connection_id=connection_id)

    trace_event(
        context.settings,
        presentation_request_message,
        outcome="presentation_exchange_send_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(
    tags=["present-proof"],
    summary="Sends a presentation request in reference to a proposal",
)
@match_info_schema(PresExIdMatchInfoSchema())
@request_schema(V10PresentationSendRequestRequestSchema())
@response_schema(V10PresentationExchangeSchema(), 200)
async def presentation_exchange_send_bound_request(request: web.BaseRequest):
    """
    Request handler for sending a presentation request free from any proposal.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    presentation_exchange_id = request.match_info["pres_ex_id"]
    pres_ex_record = await V10PresentationExchange.retrieve_by_id(
        context, presentation_exchange_id
    )
    if pres_ex_record.state != (V10PresentationExchange.STATE_PROPOSAL_RECEIVED):
        raise web.HTTPBadRequest(
            reason=(
                f"Presentation exchange {presentation_exchange_id} "
                f"in {pres_ex_record.state} state "
                f"(must be {V10PresentationExchange.STATE_PROPOSAL_RECEIVED})"
            )
        )
    body = await request.json()

    connection_id = body.get("connection_id")
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not connection_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    presentation_manager = PresentationManager(context)
    try:
        (
            pres_ex_record,
            presentation_request_message,
        ) = await presentation_manager.create_bound_request(pres_ex_record)
        result = pres_ex_record.serialize()
    except (BaseModelError, StorageError) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or connection_record,
            outbound_handler,
        )

    trace_msg = body.get("trace")
    presentation_request_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )
    await outbound_handler(presentation_request_message, connection_id=connection_id)

    trace_event(
        context.settings,
        presentation_request_message,
        outcome="presentation_exchange_send_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["present-proof"], summary="Sends a proof presentation")
@match_info_schema(PresExIdMatchInfoSchema())
@request_schema(V10PresentationRequestSchema())
@response_schema(V10PresentationExchangeSchema())
async def presentation_exchange_send_presentation(request: web.BaseRequest):
    """
    Request handler for sending a presentation.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]
    presentation_exchange_id = request.match_info["pres_ex_id"]
    pres_ex_record = await V10PresentationExchange.retrieve_by_id(
        context, presentation_exchange_id
    )
    if pres_ex_record.state != (V10PresentationExchange.STATE_REQUEST_RECEIVED):
        raise web.HTTPBadRequest(
            reason=(
                f"Presentation exchange {presentation_exchange_id} "
                f"in {pres_ex_record.state} state "
                f"(must be {V10PresentationExchange.STATE_REQUEST_RECEIVED})"
            )
        )

    body = await request.json()

    connection_id = pres_ex_record.connection_id
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not connection_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    presentation_manager = PresentationManager(context)
    try:
        (
            pres_ex_record,
            presentation_message,
        ) = await presentation_manager.create_presentation(
            pres_ex_record,
            {
                "self_attested_attributes": body.get("self_attested_attributes"),
                "requested_attributes": body.get("requested_attributes"),
                "requested_predicates": body.get("requested_predicates"),
            },
            comment=body.get("comment"),
        )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        try:
            if pres_ex_record.data_agreement:

                if pres_ex_record.data_agreement_status == V10PresentationExchange.DATA_AGREEMENT_OFFER:
                    # Check if data agreement is present in presentation exchange record and it is in offer state
                    # If so, then accept the data agreement and attach it to the presentation message

                    # Load data agreement offer
                    data_agreement_negotiation_offer_body: DataAgreementNegotiationOfferBody = DataAgreementNegotiationOfferBodySchema().load(
                        pres_ex_record.data_agreement
                    )

                    (data_agreement_instance, data_agreement_negotiation_accept_message) = await ada_manager.construct_data_agreement_negotiation_accept_message(
                        data_agreement_negotiation_offer_body=data_agreement_negotiation_offer_body,
                        connection_record=connection_record,
                    )

                    # Update presentation message with data agreement context decorator
                    presentation_message._decorators["data-agreement-context"] = DataAgreementContextDecorator(
                        message_type="protocol",
                        message=data_agreement_negotiation_accept_message.serialize()
                    )

                    # Update credential exchange record with data agreement
                    pres_ex_record.data_agreement = data_agreement_instance.serialize()
                    pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_ACCEPT

                    await pres_ex_record.save(context)
                else:
                    raise web.HTTPBadRequest(
                        reason="Data agreement is not in offer state.")

        except ADAManagerError as err:
            raise web.HTTPBadRequest(reason=err.roll_up) from err

        result = pres_ex_record.serialize()
    except (
        BaseModelError,
        HolderError,
        LedgerError,
        StorageError,
        WalletNotFoundError,
    ) as err:
        await internal_error(
            err,
            web.HTTPBadRequest,
            pres_ex_record or connection_record,
            outbound_handler,
        )

    trace_msg = body.get("trace")
    presentation_message.assign_trace_decorator(
        context.settings,
        trace_msg,
    )
    await outbound_handler(presentation_message, connection_id=connection_id)

    trace_event(
        context.settings,
        presentation_message,
        outcome="presentation_exchange_send_request.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["present-proof"], summary="Verify a received presentation")
@match_info_schema(PresExIdMatchInfoSchema())
@response_schema(V10PresentationExchangeSchema())
async def presentation_exchange_verify_presentation(request: web.BaseRequest):
    """
    Request handler for verifying a presentation request.

    Args:
        request: aiohttp request object

    Returns:
        The presentation exchange details

    """
    r_time = get_timer()

    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    presentation_exchange_id = request.match_info["pres_ex_id"]

    pres_ex_record = await V10PresentationExchange.retrieve_by_id(
        context, presentation_exchange_id
    )
    if pres_ex_record.state != (V10PresentationExchange.STATE_PRESENTATION_RECEIVED):
        raise web.HTTPBadRequest(
            reason=(
                f"Presentation exchange {presentation_exchange_id} "
                f"in {pres_ex_record.state} state "
                f"(must be {V10PresentationExchange.STATE_PRESENTATION_RECEIVED})"
            )
        )

    connection_id = pres_ex_record.connection_id

    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    if not connection_record.is_ready:
        raise web.HTTPForbidden(reason=f"Connection {connection_id} not ready")

    presentation_manager = PresentationManager(context)
    try:
        pres_ex_record = await presentation_manager.verify_presentation(pres_ex_record)
        result = pres_ex_record.serialize()
    except (LedgerError, BaseModelError) as err:
        await internal_error(err, web.HTTPBadRequest, pres_ex_record, outbound_handler)

    trace_event(
        context.settings,
        pres_ex_record,
        outcome="presentation_exchange_verify.END",
        perf_counter=r_time,
    )

    return web.json_response(result)


@docs(tags=["present-proof"], summary="Remove an existing presentation exchange record")
@match_info_schema(PresExIdMatchInfoSchema())
async def presentation_exchange_remove(request: web.BaseRequest):
    """
    Request handler for removing a presentation exchange record.

    Args:
        request: aiohttp request object

    """
    context = request.app["request_context"]
    outbound_handler = request.app["outbound_message_router"]

    presentation_exchange_id = request.match_info["pres_ex_id"]
    pres_ex_record = None
    try:
        pres_ex_record: V10PresentationExchange = await V10PresentationExchange.retrieve_by_id(
            context, presentation_exchange_id
        )
        await pres_ex_record.delete_record(context)

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Delete data agreement instance metadata
        await ada_manager.delete_data_agreement_instance_metadata(
            tag_query={
                "data_exchange_record_id": presentation_exchange_id
            }
        )

    except StorageNotFoundError as err:
        await internal_error(err, web.HTTPNotFound, pres_ex_record, outbound_handler)
    except StorageError as err:
        await internal_error(err, web.HTTPBadRequest, pres_ex_record, outbound_handler)

    return web.json_response({})


@docs(tags=["present-proof"], summary="Send a presentation request in reference to a data agreement")
@request_schema(SendPresentationRequestForDataAgreementRequestSchema())
async def send_presentation_request_for_data_agreement(request: web.BaseRequest):
    """
    Request handler to sent a presentation request in reference to a data agreement.

    Args:
        request: aiohttp request object
    """

    # Retrieve context
    context = request.app["request_context"]

    # Outbound message handler
    outbound_handler = request.app["outbound_message_router"]

    # Request payload
    body = await request.json()
    data_agreement_id = body.get("data_agreement_id")
    connection_id = body.get("connection_id")

    # Fetch the connection record

    connection_record = None
    try:
        connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")
    except (
        StorageNotFoundError,
        BaseModelError,
    ) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    # Fetch data agreement

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

        # Check if data agreement method-of-use is data-using-service
        if old_data_agreement_record.method_of_use != DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:
            raise web.HTTPBadRequest(
                reason=f"Data agreement method-of-use must be {DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE}"
            )

        # Construct presentation request message.

        indy_proof_request = old_data_agreement_record.data_agreement_proof_presentation_request
        comment = indy_proof_request.pop("comment")

        if not indy_proof_request.get("nonce"):
            indy_proof_request["nonce"] = await generate_pr_nonce()

        presentation_request_message = PresentationRequest(
            comment=comment,
            request_presentations_attach=[
                AttachDecorator.from_indy_dict(
                    indy_dict=indy_proof_request,
                    ident=ATTACH_DECO_IDS[PRESENTATION_REQUEST],
                )
            ],
        )

        # Construct presentation exchange record

        presentation_manager = PresentationManager(context)
        pres_ex_record = None
        try:
            (pres_ex_record) = await presentation_manager.create_exchange_for_request(
                connection_id=connection_id,
                presentation_request_message=presentation_request_message,
            )
            result = pres_ex_record.serialize()
        except (BaseModelError, StorageError) as err:
            await internal_error(
                err,
                web.HTTPBadRequest,
                pres_ex_record or connection_record,
                outbound_handler,
            )

        # Initialize ADA manager
        ada_manager = ADAManager(context)

        # Construct data agreement offer message.
        data_agreement_offer_message = await ada_manager.construct_data_agreement_offer_message(
            connection_record=connection_record,
            data_agreement_template_record=old_data_agreement_record,
        )

        # Add data agreement context decorator
        presentation_request_message._decorators["data-agreement-context"] = DataAgreementContextDecorator(
            message_type="protocol",
            message=data_agreement_offer_message.serialize()
        )

        pres_ex_record.presentation_request_dict = presentation_request_message.serialize()
        pres_ex_record.data_agreement = data_agreement_offer_message.body.serialize()
        pres_ex_record.data_agreement_id = data_agreement_offer_message.body.data_agreement_id
        pres_ex_record.data_agreement_template_id = data_agreement_offer_message.body.data_agreement_template_id
        pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_OFFER
        await pres_ex_record.save(context)

        # Save data agreement instance metadata
        await ada_manager.store_data_agreement_instance_metadata(
            data_agreement_id=data_agreement_offer_message.body.data_agreement_id,
            data_agreement_template_id=data_agreement_offer_message.body.data_agreement_template_id,
            data_exchange_record_id=pres_ex_record.presentation_exchange_id,
            method_of_use=data_agreement_offer_message.body.method_of_use
        )

        result = pres_ex_record.serialize()

    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    await outbound_handler(presentation_request_message, connection_id=connection_id)

    return web.json_response(result)


@docs(
    tags=["present-proof"], summary="Send data agreement reject message for a presentation request"
)
@match_info_schema(PresExIdMatchInfoSchema())
@response_schema(V10PresentationExchangeSchema(), 200)
async def send_data_agreement_reject_message_for_presentation_request(request: web.BaseRequest):
    """
    Request handler for sending data agreement reject message for presentation request

    Args:
        request: aiohttp request object

    """

    # Initialize request context
    context = request.app["request_context"]

    # Initialize outbound handler
    outbound_handler = request.app["outbound_message_router"]

    # Path parameters
    presentation_exchange_id = request.match_info["pres_ex_id"]

    pres_ex_record = None
    try:
        # Fetch presentation exchange record
        pres_ex_record: V10PresentationExchange = await V10PresentationExchange.retrieve_by_id(
            context, presentation_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    if not pres_ex_record.state == V10PresentationExchange.STATE_REQUEST_RECEIVED:
        raise web.HTTPBadRequest(
            reason=f"Presentation exchange must be in {V10PresentationExchange.STATE_REQUEST_RECEIVED} state in order to reject the offer.")

    if not pres_ex_record.data_agreement:
        raise web.HTTPBadRequest(reason=f"Data agreement is not available.")

    if not pres_ex_record.data_agreement_status == V10PresentationExchange.DATA_AGREEMENT_OFFER:
        raise web.HTTPBadRequest(
            reason=f"Data agreement must be in offer state to reject it."
        )

    # Send data agreement reject message

    data_agreement_negotiation_offer_body: DataAgreementNegotiationOfferBody = DataAgreementNegotiationOfferBodySchema().load(
        pres_ex_record.data_agreement
    )

    # Initialize ADA manager
    ada_manager = ADAManager(context)

    connection_record = None
    connection_id = pres_ex_record.connection_id
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

        # Update presentation exchange record with data agreement
        pres_ex_record.data_agreement = data_agreement_instance.serialize()
        pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_REJECT

        await pres_ex_record.save(context)

        await outbound_handler(data_agreement_negotiation_reject_message, connection_id=pres_ex_record.connection_id)

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(pres_ex_record.serialize())


@docs(
    tags=["present-proof"], summary="Send data agreement negotiation problem report message"
)
@match_info_schema(PresExIdMatchInfoSchema())
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
    presentation_exchange_id = request.match_info["pres_ex_id"]

    # Request payload
    body = await request.json()
    explain = body.get("explain", "")
    problem_code = body.get("problem_code", "")

    pres_ex_record = None
    try:
        # Fetch presentation exchange record
        pres_ex_record: V10PresentationExchange = await V10PresentationExchange.retrieve_by_id(
            context, presentation_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    if not pres_ex_record.data_agreement:
        raise web.HTTPBadRequest(reason=f"Data agreement is not available.")

    # Initialize ADA manager
    ada_manager = ADAManager(context)

    connection_record = None
    connection_id = pres_ex_record.connection_id
    try:
        connection_record = await ConnectionRecord.retrieve_by_id(
            context, connection_id
        )
        if not connection_record.is_ready:
            raise web.HTTPForbidden(
                reason=f"Connection {connection_id} not ready")

        data_agreement_negotiation_problem_report = await ada_manager.construct_data_agreement_negotiation_problem_report_message(
            connection_record=connection_record,
            data_agreement_id=pres_ex_record.data_agreement_id,
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
    tags=["present-proof"], summary="Send data agreement termination message."
)
@match_info_schema(PresExIdMatchInfoSchema())
@response_schema(V10PresentationExchangeSchema(), 200)
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
    presentation_exchange_id = request.match_info["pres_ex_id"]

    pres_ex_record = None
    try:
        # Fetch presentation exchange record
        pres_ex_record: V10PresentationExchange = await V10PresentationExchange.retrieve_by_id(
            context, presentation_exchange_id
        )
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    if not pres_ex_record.data_agreement:
        raise web.HTTPBadRequest(reason=f"Data agreement is not available.")

    if not pres_ex_record.data_agreement_status == V10PresentationExchange.DATA_AGREEMENT_ACCEPT:
        raise web.HTTPBadRequest(
            reason=f"Data agreement must be in accept state to terminate it."
        )

    # Send data agreement terminate message

    data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
        pres_ex_record.data_agreement
    )

    # Initialize ADA manager
    ada_manager = ADAManager(context)

    connection_record = None
    connection_id = pres_ex_record.connection_id
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

        # Update presentation exchange record with data agreement
        pres_ex_record.data_agreement = data_agreement_instance.serialize()
        pres_ex_record.data_agreement_status = V10PresentationExchange.DATA_AGREEMENT_TERMINATE

        await pres_ex_record.save(context)

        await outbound_handler(data_agreement_terminate_message, connection_id=pres_ex_record.connection_id)

    except (ADAManagerError, StorageError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(pres_ex_record.serialize())


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get(
                "/present-proof/records", presentation_exchange_list, allow_head=False
            ),
            web.get(
                "/present-proof/records/{pres_ex_id}",
                presentation_exchange_retrieve,
                allow_head=False,
            ),
            web.get(
                "/present-proof/records/{pres_ex_id}/credentials",
                presentation_exchange_credentials_list,
                allow_head=False,
            ),
            web.post(
                "/present-proof/send-proposal",
                presentation_exchange_send_proposal,
            ),
            web.post(
                "/present-proof/create-request",
                presentation_exchange_create_request,
            ),
            web.post(
                "/present-proof/send-request",
                presentation_exchange_send_free_request,
            ),
            web.post(
                "/present-proof/records/{pres_ex_id}/send-request",
                presentation_exchange_send_bound_request,
            ),
            web.post(
                "/present-proof/records/{pres_ex_id}/send-presentation",
                presentation_exchange_send_presentation,
            ),
            web.post(
                "/present-proof/records/{pres_ex_id}/verify-presentation",
                presentation_exchange_verify_presentation,
            ),
            web.delete(
                "/present-proof/records/{pres_ex_id}",
                presentation_exchange_remove,
            ),
            web.post(
                "/present-proof/data-agreement-negotiation/offer",
                send_presentation_request_for_data_agreement,
            ),
            web.post(
                "/present-proof/records/{pres_ex_id}/data-agreement-negotiation/reject",
                send_data_agreement_reject_message_for_presentation_request,
            ),
            web.post(
                "/present-proof/records/{pres_ex_id}/data-agreement-negotiation/problem-report",
                send_data_agreement_negotiation_problem_report,
            ),
            web.post(
                "/present-proof/records/{pres_ex_id}/data-agreement-termination/terminate",
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
            "name": "present-proof",
            "description": "Proof presentation",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
