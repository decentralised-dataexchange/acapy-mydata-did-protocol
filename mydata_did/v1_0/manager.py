import base64
import logging
import json
import os
import time
import uuid
import typing

import aiohttp

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.connections.models.connection_target import ConnectionTarget
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.responder import BaseResponder
from aries_cloudagent.core.dispatcher import DispatcherResponder
from aries_cloudagent.transport.inbound.receipt import MessageReceipt
from aries_cloudagent.core.error import BaseError
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.indy import IndyStorage
from aries_cloudagent.storage.error import (
    StorageNotFoundError,
    StorageDuplicateError,
    StorageError
)
from aries_cloudagent.wallet.indy import IndyWallet
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.messaging.decorators.default import DecoratorSet
from aries_cloudagent.transport.pack_format import PackWireFormat
from aries_cloudagent.transport.wire_format import BaseWireFormat
from aries_cloudagent.messaging.decorators.transport_decorator import TransportDecorator
from aries_cloudagent.protocols.connections.v1_0.manager import (
    ConnectionManager,
    ConnectionManagerError
)
from aries_cloudagent.protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitation
)
from aries_cloudagent.indy.util import generate_pr_nonce
from aries_cloudagent.messaging.decorators.attach_decorator import AttachDecorator
from aries_cloudagent.messaging.util import str_to_epoch

from dexa_sdk.agreements.da.v1_0.records.da_qrcode_record import (
    DataAgreementQRCodeRecord
)

from .messages.read_did import ReadDIDMessage, ReadDIDMessageBody
from .messages.read_did_response import ReadDIDResponseMessage, ReadDIDResponseMessageSchema
from .messages.problem_report import (
    MyDataDIDProblemReportMessage,
    MyDataDIDProblemReportMessageReason,
    DataAgreementNegotiationProblemReport
)
from .messages.data_agreement_offer import (
    DataAgreementNegotiationOfferMessage,
    DataAgreementNegotiationOfferMessageSchema
)
from .messages.data_agreement_accept import (
    DataAgreementNegotiationAcceptMessage,
    DataAgreementNegotiationAcceptMessageSchema
)
from .messages.data_agreement_reject import (
    DataAgreementNegotiationRejectMessage,
)
from .messages.data_agreement_terminate import (
    DataAgreementTerminationTerminateMessage,
)
from .messages.data_agreement_qr_code_initiate import DataAgreementQrCodeInitiateMessage
from .messages.data_agreement_qr_code_problem_report import (
    DataAgreementQrCodeProblemReport,
    DataAgreementQrCodeProblemReportReason
)
from .messages.json_ld_processed import JSONLDProcessedMessage
from .messages.json_ld_processed_response import JSONLDProcessedResponseMessage
from .messages.json_ld_problem_report import JSONLDProblemReport, JSONLDProblemReportReason
from .messages.data_controller_details import DataControllerDetailsMessage
from .messages.data_controller_details_response import DataControllerDetailsResponseMessage
from .messages.existing_connections import ExistingConnectionsMessage

from .models.data_agreement_model import (
    DATA_AGREEMENT_V1_SCHEMA_CONTEXT,
    DataAgreementV1,
    DataAgreementV1Schema
)
from .models.diddoc_model import (
    MyDataDIDResponseBody,
    MyDataDIDDoc,
)
from .models.exchange_records.data_agreement_record import DataAgreementV1Record
from .models.data_agreement_negotiation_offer_model import (
    DataAgreementNegotiationOfferBody,
    DataAgreementEvent,
    DataAgreementProof,
    DataAgreementProofSchema
)
from .models.data_agreement_instance_model import DataAgreementInstance, DataAgreementInstanceSchema
from .models.data_agreement_negotiation_accept_model import DataAgreementNegotiationAcceptBody
from .models.data_agreement_negotiation_reject_model import DataAgreementNegotiationRejectBody
from .models.data_agreement_termination_terminate_model import DataAgreementTerminationTerminateBody
from .models.data_agreement_qr_code_initiate_model import DataAgreementQrCodeInitiateBody
from .models.json_ld_processed_response_model import JSONLDProcessedResponseBody
from .models.json_ld_processed_model import JSONLDProcessedBody
from .models.data_controller_model import DataController, DataControllerSchema
from .models.existing_connections_model import ExistingConnectionsBody
from .utils.did.mydata_did import DIDMyData
from .utils.wallet.key_type import KeyType
from .utils.jsonld import ED25519_2018_CONTEXT_URL
from .utils.jsonld.data_agreement import sign_data_agreement
from .utils.util import current_datetime_in_iso8601
from .utils.jsonld.create_verify_data import create_verify_data

from .decorators.data_agreement_context_decorator import (
    DataAgreementContextDecoratorSchema,
    DataAgreementContextDecorator
)
from .message_types import (
    DATA_AGREEMENT_NEGOTIATION_OFFER,
    DATA_AGREEMENT_NEGOTIATION_ACCEPT,
)

from ..patched_protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange
)
from ..patched_protocols.present_proof.v1_0.models.presentation_exchange import (
    V10PresentationExchange
)
from ..patched_protocols.present_proof.v1_0.messages.presentation_request import PresentationRequest
from ..patched_protocols.present_proof.v1_0.message_types import (
    ATTACH_DECO_IDS,
    PRESENTATION_REQUEST
)
from ..patched_protocols.present_proof.v1_0.manager import PresentationManager


class ADAManagerError(BaseError):
    """ADA manager error"""


class ADAManager:

    # Record for storing data agreement instance metadata (client)
    RECORD_TYPE_DATA_AGREEMENT_INSTANCE_METADATA = "data_agreement_instance_metadata"

    # Record for keeping track of DIDs that are registered in the DID registry (MyData DID registry)
    RECORD_TYPE_MYDATA_DID_REGISTRY_DID_INFO = "mydata_did_registry_did_info"

    # Record for keeping metadata about data agreement QR codes (client)
    RECORD_TYPE_DATA_AGREEMENT_QR_CODE_METADATA = "data_agreement_qr_code_metadata"

    # Temporary record for keeping personal data of unpublished (or draft) data agreements
    RECORD_TYPE_TEMPORARY_DATA_AGREEMENT_PERSONAL_DATA = "temporary_data_agreement_personal_data"

    # Record for data controller details
    RECORD_TYPE_DATA_CONTROLLER_DETAILS = "data_controller_details"

    # Record for existing connection details.
    RECORD_TYPE_EXISTING_CONNECTION = "existing_connection"

    DATA_AGREEMENT_RECORD_TYPE = "dataagreement_record"

    def __init__(self, context: InjectionContext) -> None:
        self._context = context
        self._logger = logging.getLogger(__name__)

    @property
    def context(self) -> InjectionContext:
        return self._context

    async def process_read_did_message(self,
                                       read_did_message: ReadDIDMessage,
                                       receipt: MessageReceipt):
        """
        Process read-did DIDComm message
        """

        # Storage instance from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Responder instance from context
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        # From and To DIDs of the recieved message
        create_did_message_from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)
        create_did_message_to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)

        # From and To DIDs for the response messages
        response_message_from_did = create_did_message_to_did
        response_message_to_did = create_did_message_from_did

        mydata_did_registry_did_info_record = None
        try:

            # Fetch DID from wallet
            mydata_did_registry_did_info_record = await storage.search_records(
                type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REGISTRY_DID_INFO,
                tag_query={"did": read_did_message.body.did}
            ).fetch_single()

        except (StorageNotFoundError, StorageDuplicateError):
            # Send problem-report message.

            mydata_did_problem_report = MyDataDIDProblemReportMessage(
                problem_code=MyDataDIDProblemReportMessageReason.DID_NOT_FOUND.value,
                explain="DID not found.",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=round(time.time() * 1000)
            )

            # Assign thread id
            mydata_did_problem_report.assign_thread_id(
                thid=read_did_message._id)

            if responder:
                await responder.send_reply(mydata_did_problem_report)

            return

        # Send read-did-response message
        read_did_response_message = ReadDIDResponseMessage(
            from_did=response_message_from_did.did,
            to_did=response_message_to_did.did,
            created_time=round(time.time() * 1000),
            body=MyDataDIDResponseBody(
                did_doc=MyDataDIDDoc.from_json(
                    mydata_did_registry_did_info_record.value),
                version=mydata_did_registry_did_info_record.tags.get(
                    "version"),
                status=mydata_did_registry_did_info_record.tags.get("status")
            )
        )

        # Assign thread id
        read_did_response_message.assign_thread_id(
            thid=read_did_message._id)

        if responder:
            await responder.send_reply(read_did_response_message)

    async def process_read_did_response_message(
        self,
        read_did_response_message: ReadDIDResponseMessage,
        receipt: MessageReceipt
    ):
        """
        Process read-did-response DIDComm message
        """

        pass

    async def send_read_did_message(self, did: str):
        """
        Send read-did DIDComm message
        """

        pass

    async def store_data_agreement_instance_metadata(self, *, data_agreement_id: str = None, data_agreement_template_id: str = None, method_of_use: str = None, data_exchange_record_id: str = None) -> None:
        """Store data agreement instance metadata"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        data_instance_metadata_record = StorageRecord(
            self.RECORD_TYPE_DATA_AGREEMENT_INSTANCE_METADATA,
            data_agreement_id,
            {
                "data_agreement_id": data_agreement_id,
                "data_agreement_template_id": data_agreement_template_id,
                "method_of_use": method_of_use,
                "data_exchange_record_id": data_exchange_record_id
            }
        )

        await storage.add_record(data_instance_metadata_record)

    async def delete_data_agreement_instance_metadata(self, *, tag_query: dict = None) -> None:
        """Delete data agreement instance metadata"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        storage_records = await storage.search_records(
            type_filter=self.RECORD_TYPE_DATA_AGREEMENT_INSTANCE_METADATA,
            tag_query=tag_query
        ).fetch_all()

        for storage_record in storage_records:
            await storage.delete_record(storage_record)

    async def query_data_agreement_instance_metadata(self, *, tag_query: dict = None) -> typing.List[StorageRecord]:
        """Query data agreement instance metadata"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        storage_records = await storage.search_records(
            type_filter=self.RECORD_TYPE_DATA_AGREEMENT_INSTANCE_METADATA,
            tag_query=tag_query
        ).fetch_all()

        return storage_records

    async def resolve_remote_mydata_did(self, *, mydata_did: str) -> MyDataDIDResponseBody:
        """Resolve remote MyData DID"""

        # Initialize DID MyData
        mydata_did = DIDMyData.from_did(mydata_did)

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Get pack format from context
        pack_format: PackWireFormat = await self.context.inject(BaseWireFormat)

        # Fetch connection record marked as MyData DID registry
        connection_record, err = await self.fetch_mydata_did_registry_connection_record()
        if err:
            raise ADAManagerError(
                "Failed to fetch MyData DID registry connection record")

        # Construct read-did message
        # from_did
        pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
        from_did = DIDMyData.from_public_key_b58(
            pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

        # to_did
        to_did = DIDMyData.from_public_key_b58(
            connection_record.their_did, key_type=KeyType.ED25519)

        # Create read-did message
        read_did_message = ReadDIDMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=ReadDIDMessageBody(
                did=mydata_did.did
            )
        )

        # Add transport decorator
        read_did_message._decorators["transport"] = TransportDecorator(
            return_route="all"
        )

        # Initialise connection manager
        connection_manager = ConnectionManager(self.context)

        # Fetch connection targets
        connection_targets = await connection_manager.fetch_connection_targets(connection_record)

        if len(connection_targets) == 0:
            raise ADAManagerError("No connection targets found")

        connection_target: ConnectionTarget = connection_targets[0]

        # Pack message
        packed_message = await pack_format.pack(
            context=self.context,
            message_json=read_did_message.serialize(as_string=True),
            recipient_keys=connection_target.recipient_keys,
            routing_keys=None,
            sender_key=connection_target.sender_key,
        )

        headers = {
            "Content-Type": "application/ssi-agent-wire"
        }
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.post(connection_target.endpoint, data=packed_message) as response:
                if response.status != 200:
                    raise ADAManagerError(
                        f"HTTP request failed with status code {response.status}")

                message_body = await response.read()

                unpacked = await wallet.unpack_message(message_body)

                (
                    message_json,
                    sender_verkey,
                    recipient_verkey,
                ) = unpacked

                message_json = json.loads(message_json)

                if "problem-report" in message_json["@type"]:
                    raise ADAManagerError(
                        f"Problem report received with problem-code:{message_json['problem-code']} and reason: {message_json['explain']}")

                if "read-did-response" in message_json["@type"]:
                    read_did_response_message: ReadDIDResponseMessage = ReadDIDResponseMessageSchema().load(message_json)

                    if read_did_response_message.body.status == "revoked":
                        raise ADAManagerError(
                            f"MyData DID {mydata_did.did} is revoked"
                        )

                    return read_did_response_message.body

    async def fetch_firebase_config_from_os_environ(self) -> dict:
        """Fetch firebase config from os environ"""

        # Retrieve config from os environ
        firebase_web_api_key = os.environ.get("FIREBASE_WEB_API_KEY")
        firebase_domain_uri_prefix = os.environ.get(
            "FIREBASE_DOMAIN_URI_PREFIX")
        firebase_android_android_package_name = os.environ.get(
            "FIREBASE_ANDROID_ANDROID_PACKAGE_NAME")
        firebase_ios_bundle_id = os.environ.get("FIREBASE_IOS_BUNDLE_ID")
        firebase_ios_appstore_id = os.environ.get("FIREBASE_IOS_APPSTORE_ID")

        if not firebase_web_api_key:
            raise ADAManagerError(
                "Failed to retrieve firebase web api key from os environ")

        if not firebase_domain_uri_prefix:
            raise ADAManagerError(
                "Failed to retrieve firebase domain uri prefix from os environ")

        if not firebase_android_android_package_name:
            raise ADAManagerError(
                "Failed to retrieve firebase android android package name from os environ")

        if not firebase_ios_bundle_id:
            raise ADAManagerError(
                "Failed to retrieve firebase ios bundle id from os environ")

        if not firebase_ios_appstore_id:
            raise ADAManagerError(
                "Failed to retrieve firebase ios appstore id from os environ")

        return {
            "firebase_web_api_key": firebase_web_api_key,
            "firebase_domain_uri_prefix": firebase_domain_uri_prefix,
            "firebase_android_android_package_name": firebase_android_android_package_name,
            "firebase_ios_bundle_id": firebase_ios_bundle_id,
            "firebase_ios_appstore_id": firebase_ios_appstore_id,
        }

    async def fetch_igrantio_config_from_os_environ(self) -> dict:
        """Fetch iGrant.io config from os environ"""

        igrantio_org_id = os.environ.get("IGRANTIO_ORG_ID")

        igrantio_org_api_key = os.environ.get("IGRANTIO_ORG_API_KEY")

        igrantio_org_api_key_secret = os.environ.get(
            "IGRANTIO_ORG_API_KEY_SECRET")

        igrantio_endpoint_url = os.environ.get("IGRANTIO_ENDPOINT_URL")

        if not igrantio_org_id:
            raise ADAManagerError(
                "Failed to retrieve igrantio org id from os environ")

        if not igrantio_org_api_key:
            raise ADAManagerError(
                "Failed to retrieve igrantio org api key from os environ")

        if not igrantio_org_api_key_secret:
            raise ADAManagerError(
                "Failed to retrieve igrantio org api key secret from os environ")

        if not igrantio_endpoint_url:
            raise ADAManagerError(
                "Failed to retrieve igrantio endpoint url from os environ")

        return {
            "igrantio_org_id": igrantio_org_id,
            "igrantio_org_api_key": igrantio_org_api_key,
            "igrantio_org_api_key_secret": igrantio_org_api_key_secret,
            "igrantio_endpoint_url": igrantio_endpoint_url,
        }

    async def process_json_ld_processed_message(self, json_ld_processed_message: JSONLDProcessedMessage, receipt: MessageReceipt) -> None:

        # Storage instance
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Wallet instance
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Responder instance
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        # From and To MyData DIDs
        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)
        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)

        try:
            # Base64 decode data_base64
            data_base64_decoded = base64.b64decode(
                json_ld_processed_message.body.data_base64)

            # JSON load data_base64
            data_json = json.loads(data_base64_decoded)

            # Base64 decode signature_options_base64
            signature_options_base64_decoded = base64.b64decode(
                json_ld_processed_message.body.signature_options_base64)

            # JSON load signature_options_base64
            signature_options_json = json.loads(
                signature_options_base64_decoded)

            # verify_data function
            framed, combine_hash = create_verify_data(
                data_json, signature_options_json, json_ld_processed_message.body.proof_chain)

            # Base64 encode framed
            framed_base64_encoded = base64.b64encode(
                json.dumps(framed).encode("utf-8")).decode("utf-8")

            # Base64 encode combine_hash
            combine_hash_base64_encoded = base64.b64encode(
                combine_hash.encode("utf-8")).decode("utf-8")

            # Construct JSONLD Processed Response Message
            json_ld_processed_response_message = JSONLDProcessedResponseMessage(
                from_did=from_did.did,
                to_did=to_did.did,
                created_time=round(time.time() * 1000),
                body=JSONLDProcessedResponseBody(
                    framed_base64=framed_base64_encoded,
                    combined_hash_base64=combine_hash_base64_encoded
                )
            )

            if responder:
                await responder.send_reply(json_ld_processed_response_message, connection_id=self.context.connection_record.connection_id)

        except Exception as err:
            # Send problem report
            json_ld_problem_report_message = JSONLDProblemReport(
                problem_code=JSONLDProblemReportReason.INVALID_INPUT.value,
                explain=str(err),
                from_did=from_did.did,
                to_did=to_did.did,
                created_time=round(time.time() * 1000)
            )

            if responder:
                await responder.send_reply(json_ld_problem_report_message, connection_id=self.context.connection_record.connection_id)

    async def send_json_ld_processed_message(self, *, connection_id: str, data: dict, signature_options: dict, proof_chain: bool) -> None:
        """Send JSON-LD Processed Message to remote agent."""

        # Responder instance
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        try:

            # Retrieve connection record by id
            connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
                self.context,
                connection_id
            )

        except StorageError as err:

            raise ADAManagerError(
                f"Failed to retrieve connection record: {err}"
            )

        # From and to mydata dids
        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            connection_record.my_did, key_type=KeyType.ED25519
        )
        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            connection_record.their_did, key_type=KeyType.ED25519
        )

        # Base64 encode data
        data_base64 = base64.b64encode(json.dumps(
            data).encode("utf-8")).decode("utf-8")

        # Base64 encode signature_options
        signature_options_base64 = base64.b64encode(json.dumps(
            signature_options).encode("utf-8")).decode("utf-8")

        # Construct JSONLD Processed Message
        json_ld_processed_message = JSONLDProcessedMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=JSONLDProcessedBody(
                data_base64=data_base64,
                signature_options_base64=signature_options_base64,
                proof_chain=proof_chain
            )
        )

        # Send JSONLD Processed Message
        if responder:
            await responder.send_reply(json_ld_processed_message, connection_id=connection_record.connection_id)

    async def generate_firebase_dynamic_link_for_connection_invitation(self, conn_id: str) -> str:
        """Generate a Firebase Dynamic Link for a connection invitation."""

        # Fetch config from os environ
        config = await self.fetch_firebase_config_from_os_environ()

        # Fetch connection record

        try:

            connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
                self.context,
                conn_id
            )

        except StorageError as err:
            raise ADAManagerError(
                f"Failed to fetch connection record: {err}"
            )

        # Retreive connection invitation

        connection_invitation: ConnectionInvitation = await connection_record.retrieve_invitation(self.context)

        # Get the invitation url

        invitation_url = connection_invitation.to_url()

        # Generate the dynamic link

        # Construct firebase payload
        payload = {
            "dynamicLinkInfo": {
                "domainUriPrefix": config["firebase_domain_uri_prefix"],
                "link": invitation_url,
                "androidInfo": {
                    "androidPackageName": config["firebase_android_android_package_name"],
                },
                "iosInfo": {
                    "iosBundleId": config["firebase_ios_bundle_id"],
                    "iosAppStoreId": config["firebase_ios_appstore_id"],
                }
            },
            "suffix": {
                "option": "UNGUESSABLE"
            }
        }

        firebase_dynamic_link_endpoint = "https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key=" + \
            config["firebase_web_api_key"]

        jresp = {}
        async with aiohttp.ClientSession() as session:
            async with session.post(firebase_dynamic_link_endpoint, json=payload) as resp:
                if resp.status == 200:
                    jresp = await resp.json()
                else:
                    tresp = await resp.text()
                    raise ADAManagerError(
                        f"Failed to generate firebase dynamic link for connection-invitation: {resp.status} {tresp}"
                    )

        return jresp["shortLink"]

    async def fetch_org_details_from_igrantio(self) -> str:
        """
        Fetch org details from iGrant.io.
        """

        # fetch iGrant.io config from os environment
        igrantio_config = await self.fetch_igrantio_config_from_os_environ()

        # Construct iGrant.io organisation detail endpoint URL
        igrantio_organisation_detail_url = f"{igrantio_config['igrantio_endpoint_url']}/v1/organizations/{igrantio_config['igrantio_org_id']}"

        # Construct request headers
        request_headers = {
            "Authorization": f"ApiKey {igrantio_config['igrantio_org_api_key']}"
        }

        data_controller = json.dumps({})

        async with aiohttp.ClientSession(headers=request_headers) as session:
            async with session.get(igrantio_organisation_detail_url) as resp:
                if resp.status == 200:
                    jresp = await resp.json()

                    if "Organization" in jresp:
                        organization_details = jresp["Organization"]

                        exclude_keys = [
                            "BillingInfo",
                            "Admins",
                            "HlcSupport",
                            "DataRetention",
                            "Enabled",
                            "Subs"
                        ]

                        for exclude_key in exclude_keys:
                            organization_details.pop(exclude_key, None)

                        data_controller = DataController(
                            organisation_id=organization_details["ID"],
                            organisation_name=organization_details["Name"],
                            cover_image_url=organization_details["CoverImageURL"] + "/web",
                            logo_image_url=organization_details["LogoImageURL"] + "/web",
                            location=organization_details["Location"],
                            organisation_type=organization_details["Type"]["Type"],
                            description=organization_details["Description"],
                            policy_url=organization_details["PolicyURL"],
                            eula_url=organization_details["EulaURL"]
                        ).to_json()

        return data_controller

    async def process_existing_connections_message(self, existing_connections_message: ExistingConnectionsMessage, receipt: MessageReceipt) -> None:
        """Processing connections/1.0/exists message."""

        # Storage instance
        storage = await self.context.inject(BaseStorage)

        invitation_key = receipt.recipient_verkey

        # fetch current connection record using invitation key
        connection = await ConnectionRecord.retrieve_by_invitation_key(
            self.context, invitation_key)

        # Fetch existing connections record for the current connection.

        existing_connection = await storage.search_records(
            type_filter=self.RECORD_TYPE_EXISTING_CONNECTION,
            tag_query={
                "connection_id": connection.connection_id
            }
        ).fetch_all()

        if existing_connection:
            # delete existing connections record
            existing_connection = existing_connection[0]
            await storage.delete_record(existing_connection)

        existing_connection = None

        # fetch the existing connection by did
        existing_connection = await ConnectionRecord.retrieve_by_did(
            self.context, their_did=None, my_did=existing_connections_message.body.theirdid)

        # create existing_connections record with connection_id, did, connection_status available
        record_tags = {
            "existing_connection_id": existing_connection.connection_id,
            "my_did": existing_connection.my_did,
            "connection_status": "available",
            "connection_id": connection.connection_id
        }

        record = StorageRecord(
            self.RECORD_TYPE_EXISTING_CONNECTION,
            connection.connection_id,
            record_tags
        )
        await storage.add_record(record)

        # updating the current connection invitation status to inactive
        connection.state = ConnectionRecord.STATE_INACTIVE
        await connection.save(context=self.context)

    async def send_existing_connections_message(self, theirdid: str, connection_id: str) -> None:
        """Send existing connections message."""

        # Responder instance
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        try:
            connection_mgr = ConnectionManager(self.context)

            # Retrieve connection record by id
            connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
                self.context,
                connection_id
            )

            connection_invitation: ConnectionInvitation = await connection_record.retrieve_invitation(self.context)

            request = await connection_mgr.create_request(connection_record)

        except StorageError as err:

            raise ADAManagerError(
                f"Failed to retrieve connection record: {err}"
            )

        # From and to mydata dids
        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            request.connection.did, key_type=KeyType.ED25519
        )
        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            request.connection.did, key_type=KeyType.ED25519
        )

        # Construct ExistingConnectionsMessage Message
        existing_connections_message = ExistingConnectionsMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=ExistingConnectionsBody(
                theirdid=theirdid
            )
        )

        # Send message
        if responder:
            await responder.send_reply(
                existing_connections_message,
                connection_id=connection_record.connection_id
            )

    async def fetch_existing_connections_record_for_current_connection(self, connection_id: str) -> dict:
        """
        Fetch existing connections record for the current connection.
        """

        # Storage instance
        storage = await self.context.inject(BaseStorage)

        # Fetch existing connections record for the current connection.

        existing_connection = await storage.search_records(
            type_filter=self.RECORD_TYPE_EXISTING_CONNECTION,
            tag_query={
                "connection_id": connection_id
            }
        ).fetch_all()

        if existing_connection:
            existing_connection = existing_connection[0]
            return existing_connection.tags
        else:
            return {}

    def serialize_data_agreement_record(self, *, data_agreement_records: typing.List[DataAgreementV1Record], is_list: bool = True, include_fields: typing.List[str] = []) -> typing.Union[typing.List[dict], dict]:
        """
        Serialize data agreement record.

        Args:
            data_agreement_record: Data agreement record.

        Returns:
            :rtype: dict: Data agreement record as dict
        """

        data_agreement_record_list = []

        assert len(data_agreement_records) > 0

        for data_agreement_record in data_agreement_records:

            temp_record = {
                "data_agreement_id": data_agreement_record.data_agreement_id,
                "state": data_agreement_record.state,
                "method_of_use": data_agreement_record.method_of_use,
                "data_agreement": data_agreement_record.data_agreement,
                "publish_flag": data_agreement_record._publish_flag,
                "delete_flag": data_agreement_record._delete_flag,
                "schema_id": data_agreement_record.schema_id,
                "cred_def_id": data_agreement_record.cred_def_id,
                "presentation_request": data_agreement_record.data_agreement_proof_presentation_request,
                "is_existing_schema": data_agreement_record._is_existing_schema,
                "created_at": str_to_epoch(data_agreement_record.created_at),
                "updated_at": str_to_epoch(data_agreement_record.updated_at)
            }

            # Include only the fields specified in the include_fields list
            if include_fields:

                # created_at must be present in the include_fields
                if "created_at" not in include_fields:
                    include_fields.append("created_at")

                # updated_at must be present in the include_fields
                if "updated_at" not in include_fields:
                    include_fields.append("updated_at")

                temp_record = {k: v for k,
                               v in temp_record.items() if k in include_fields}

            data_agreement_record_list.append(temp_record)

        # Sort data agreement records by created_at in descending order
        data_agreement_record_list = sorted(
            data_agreement_record_list, key=lambda k: k['created_at'], reverse=True)

        return data_agreement_record_list if is_list else data_agreement_record_list[0]

    @classmethod
    def serialize_connection_record(cls, connection_records: typing.List[ConnectionRecord], is_list: bool = True, include_fields: typing.List[str] = []) -> dict:
        """
        Serialize connection record.

        Args:
            connection_records: List of connection records.
            is_list: If true, serialize as list.

        Returns:
            List of serialized connection records.
        """

        connection_records_list = []
        for connection_record in connection_records:

            temp_record = {
                "state": connection_record.state,
                "invitation_mode": connection_record.invitation_mode,
                "connection_id": connection_record.connection_id,
                "created_at": str_to_epoch(connection_record.created_at),
                "updated_at": str_to_epoch(connection_record.updated_at),
                "their_did": connection_record.their_did,
                "accept": connection_record.accept,
                "initiator": connection_record.initiator,
                "invitation_key": connection_record.invitation_key,
                "routing_state": connection_record.routing_state,
                "their_label": connection_record.their_label,
                "my_did": connection_record.my_did,
            }

            # Include only the fields specified in the include_fields list
            if include_fields:

                # created_at must be present in the include_fields
                if "created_at" not in include_fields:
                    include_fields.append("created_at")

                # updated_at must be present in the include_fields
                if "updated_at" not in include_fields:
                    include_fields.append("updated_at")

                temp_record = {k: v for k,
                               v in temp_record.items() if k in include_fields}

            connection_records_list.append(temp_record)

        # Sort by created_at in descending order
        connection_records_list = sorted(
            connection_records_list, key=lambda k: k['created_at'], reverse=True)

        return connection_records_list if is_list else connection_records_list[0]

    @classmethod
    def serialize_presentation_exchange_records(cls, presentation_exchange_records: typing.List[V10PresentationExchange], is_list: bool = True, include_fields: typing.List[str] = []) -> dict:
        """
        Serialize presentation exchange records.

        Args:
            presentation_exchange_records: List of presentation exchange records.
            is_list: If true, serialize as list.

        Returns:
            List of serialized presentation exchange records.
        """

        presentation_exchange_records_list = []

        for presentation_exchange_record in presentation_exchange_records:

            temp_record = {
                "presentation_exchange_id": presentation_exchange_record.presentation_exchange_id,
                "connection_id": presentation_exchange_record.connection_id,
                "thread_id": presentation_exchange_record.thread_id,
                "initiator": presentation_exchange_record.initiator,
                "role": presentation_exchange_record.role,
                "state": presentation_exchange_record.state,
                "presentation_proposal_dict": presentation_exchange_record.presentation_proposal_dict,
                "presentation_request": presentation_exchange_record.presentation_request,
                "presentation_request_dict": presentation_exchange_record.presentation_request_dict,
                "presentation": presentation_exchange_record.presentation,
                "verified": presentation_exchange_record.verified,
                "auto_present": presentation_exchange_record.auto_present,
                "error_msg": presentation_exchange_record.error_msg,
                "data_agreement": presentation_exchange_record.data_agreement,
                "data_agreement_id": presentation_exchange_record.data_agreement_id,
                "data_agreement_template_id": presentation_exchange_record.data_agreement_template_id,
                "data_agreement_status": presentation_exchange_record.data_agreement_status,
                "data_agreement_problem_report": presentation_exchange_record.data_agreement_problem_report,
                "created_at": str_to_epoch(presentation_exchange_record.created_at),
                "updated_at": str_to_epoch(presentation_exchange_record.updated_at),
            }

            # Include only the fields specified in the include_fields list
            if include_fields:

                # created_at must be present in the include_fields
                if "created_at" not in include_fields:
                    include_fields.append("created_at")

                # updated_at must be present in the include_fields
                if "updated_at" not in include_fields:
                    include_fields.append("updated_at")

                temp_record = {k: v for k,
                               v in temp_record.items() if k in include_fields}

            presentation_exchange_records_list.append(temp_record)

        # Sort by created_at in descending order
        presentation_exchange_records_list = sorted(
            presentation_exchange_records_list, key=lambda k: k['created_at'], reverse=True)

        return presentation_exchange_records_list if is_list else presentation_exchange_records_list[0]

    @classmethod
    def serialize_credential_exchange_records(cls, credential_exchange_records: typing.List[V10CredentialExchange], is_list: bool = True, include_fields: typing.List[str] = []) -> dict:
        """
        Serialize credential exchange records.

        Args:
            credential_exchange_records: List of credential exchange records.
            is_list: If true, serialize as list.

        Returns:
            List of serialized credential exchange records.
        """

        credential_exchange_records_list = []

        for credential_exchange_record in credential_exchange_records:

            temp_record = {
                "credential_exchange_id": credential_exchange_record.credential_exchange_id,
                "connection_id": credential_exchange_record.connection_id,
                "thread_id": credential_exchange_record.thread_id,
                "initiator": credential_exchange_record.initiator,
                "role": credential_exchange_record.role,
                "state": credential_exchange_record.state,
                "credential_definition_id": credential_exchange_record.credential_definition_id,
                "schema_id": credential_exchange_record.schema_id,
                "credential_proposal_dict": credential_exchange_record.credential_proposal_dict,
                "credential_offer_dict": credential_exchange_record.credential_offer_dict,
                "credential_offer": credential_exchange_record.credential_offer,
                "credential_request": credential_exchange_record.credential_request,
                "credential_request_metadata": credential_exchange_record.credential_request_metadata,
                "credential_id": credential_exchange_record.credential_id,
                "raw_credential": credential_exchange_record.raw_credential,
                "credential": credential_exchange_record.credential,
                "auto_offer": credential_exchange_record.auto_offer,
                "auto_issue": credential_exchange_record.auto_issue,
                "auto_remove": credential_exchange_record.auto_remove,
                "error_msg": credential_exchange_record.error_msg,
                "data_agreement": credential_exchange_record.data_agreement,
                "data_agreement_id": credential_exchange_record.data_agreement_id,
                "data_agreement_template_id": credential_exchange_record.data_agreement_template_id,
                "data_agreement_status": credential_exchange_record.data_agreement_status,
                "data_agreement_problem_report": credential_exchange_record.data_agreement_problem_report,
                "created_at": str_to_epoch(credential_exchange_record.created_at),
                "updated_at": str_to_epoch(credential_exchange_record.updated_at),
            }

            # Include only the fields specified in the include_fields list
            if include_fields:

                # created_at must be present in the include_fields
                if "created_at" not in include_fields:
                    include_fields.append("created_at")

                # updated_at must be present in the include_fields
                if "updated_at" not in include_fields:
                    include_fields.append("updated_at")

                temp_record = {k: v for k,
                               v in temp_record.items() if k in include_fields}

            credential_exchange_records_list.append(temp_record)

        # Sort by created_at in descending order
        credential_exchange_records_list = sorted(
            credential_exchange_records_list, key=lambda k: k['created_at'], reverse=True)

        return credential_exchange_records_list if is_list else credential_exchange_records_list[0]
