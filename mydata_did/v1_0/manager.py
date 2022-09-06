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
    StorageSearchError,
    StorageDuplicateError,
    StorageError
)
from aries_cloudagent.wallet.indy import IndyWallet
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager
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
    DataAgreementPersonalData,
    DataAgreementV1Schema
)
from .models.diddoc_model import (
    MyDataDIDResponseBody,
    MyDataDIDDoc,
)
from .models.exchange_records.data_agreement_record import DataAgreementV1Record
from .models.exchange_records.data_agreement_personal_data_record import (
    DataAgreementPersonalDataRecord
)
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

    # Record for indication a connection is labelled as Auditor (client)
    RECORD_TYPE_AUDITOR_CONNECTION = "auditor_connection"

    # Record for indicating a connection is labelled as MyData DID registry (client)
    RECORD_TYPE_MYDATA_DID_REGISTRY_CONNECTION = "mydata_did_registry_connection"

    # Record for indicating a MyData DID is registered in the DID registry (client)
    RECORD_TYPE_MYDATA_DID_REMOTE = "mydata_did_remote"

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

    async def create_and_store_da_personal_data_in_wallet(
        self,
        personal_data: DataAgreementPersonalData,
        da_template_id: str,
        da_template_version: int
    ) -> DataAgreementPersonalDataRecord:
        """
        Create and store personal data in the wallet.
        """
        restrictions = []

        if personal_data.restrictions:
            for restriction in personal_data.restrictions:
                restrictions.append(restriction.serialize())

        new_personal_data_record = DataAgreementPersonalDataRecord(
            attribute_name=personal_data.attribute_name,
            attribute_category=personal_data.attribute_category,
            attribute_sensitive="true" if personal_data.attribute_sensitive else "false",
            attribute_description=personal_data.attribute_description,
            restrictions=restrictions,
            da_template_id=da_template_id,
            da_template_version=da_template_version,
        )

        await new_personal_data_record.save(self.context)

        return new_personal_data_record

    async def list_da_personal_data_category_from_wallet(self) -> typing.List[str]:
        """
        List personal data category in the wallet.
        """

        try:

            # Query for the old data agreement record by id
            personal_data_records: typing.List[DataAgreementPersonalDataRecord] = await DataAgreementPersonalDataRecord.query(
                self.context,
            )

            # Generate a list of category
            personal_data_category_list = [
                personal_data_record.attribute_category for personal_data_record in personal_data_records]

            # Remove duplicates
            personal_data_category_list = list(
                set(personal_data_category_list))

            return personal_data_category_list
        except StorageSearchError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch all data agreements from wallet: {e}"
            )

    async def transform_sovrin_did_to_mydata_did(self, sovrin_did: str) -> str:
        """
        Transform Sovrin DID to MyData DID.
        """

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(IndyWallet)

        # Fetch did from wallet
        did_info = await wallet.get_local_did(sovrin_did)

        # Return MyData DID
        mydata_did: DIDMyData = DIDMyData.from_public_key_b58(public_key=did_info.verkey,
                                                              key_type=KeyType.ED25519)

    async def construct_data_agreement_offer_message(self, connection_record: ConnectionRecord, data_agreement_template_record: DataAgreementV1Record) -> typing.Union[None, DataAgreementNegotiationOfferMessage]:
        """Construct data agreement offer message."""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        controller_did = await wallet.get_local_did(connection_record.my_did)

        # Principle DID from connection record
        principle_did = f"did:sov:{connection_record.their_did}"

        # Construct data agreement negotiation offer message

        data_agreement_body: DataAgreementV1 = DataAgreementV1Schema().load(
            data_agreement_template_record.data_agreement)

        data_agreement_negotiation_offer_body = DataAgreementNegotiationOfferBody(
            context=[
                DATA_AGREEMENT_V1_SCHEMA_CONTEXT,
                ED25519_2018_CONTEXT_URL
            ],
            data_agreement_id=str(uuid.uuid4()),
            data_agreement_version=1,
            data_agreement_template_id=data_agreement_body.data_agreement_template_id,
            data_agreement_template_version=data_agreement_body.data_agreement_template_version,
            pii_controller_name=data_agreement_body.pii_controller_name,
            pii_controller_url=data_agreement_body.pii_controller_url,
            usage_purpose=data_agreement_body.usage_purpose,
            usage_purpose_description=data_agreement_body.usage_purpose_description,
            legal_basis=data_agreement_body.legal_basis,
            method_of_use=data_agreement_body.method_of_use,
            principle_did=f"did:sov:{principle_did}",
            data_policy=data_agreement_body.data_policy,
            personal_data=data_agreement_body.personal_data,
            dpia=data_agreement_body.dpia,
            event=[DataAgreementEvent(
                event_id=f"did:sov:{controller_did.did}#1",
                time_stamp=current_datetime_in_iso8601(),
                did=f"did:sov:{controller_did.did}",
                state=DataAgreementEvent.STATE_OFFER
            )]
        )

        data_agreement_negotiation_offer_body_dict = data_agreement_negotiation_offer_body.serialize()

        signature_options = {
            "id": f"did:sov:{controller_did.did}#1",
            "type": "Ed25519Signature2018",
            "created": current_datetime_in_iso8601(),
            "verificationMethod": f"{controller_did.verkey}",
            "proofPurpose": "contractAgreement",
        }

        # Generate proofs
        document_with_proof: dict = await sign_data_agreement(
            data_agreement_negotiation_offer_body_dict.copy(
            ), signature_options, controller_did.verkey, wallet
        )

        data_agreement_offer_proof: DataAgreementProof = DataAgreementProofSchema().load(
            document_with_proof.get("proof"))

        # Update data agreement negotiation offer message with proof
        data_agreement_negotiation_offer_body.proof = data_agreement_offer_proof

        # Construct data agreement negotiation offer message
        data_agreement_negotiation_offer_message = DataAgreementNegotiationOfferMessage(
            from_did=controller_did.did,
            to_did=principle_did,
            created_time=round(time.time() * 1000),
            body=data_agreement_negotiation_offer_body
        )

        return data_agreement_negotiation_offer_message

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

    async def process_data_agreement_context_decorator(self, *, decorator_set: DecoratorSet) -> typing.Union[None, DataAgreementNegotiationOfferMessage, DataAgreementNegotiationAcceptMessage]:
        """Process data agreement context decorator"""

        # Check if data agreement context decorator is present
        if "data-agreement-context" not in decorator_set.keys():
            self._logger.info("Data agreement context decorator is missing")
            return None

        # Deserialize data agreement context decorator
        data_agreement_context_decorator: DataAgreementContextDecorator = DataAgreementContextDecoratorSchema(
        ).load(decorator_set["data-agreement-context"])

        # Check if data agreement context decorator message type is valid
        if data_agreement_context_decorator.message_type not in ("protocol", "non-protocol"):
            raise ADAManagerError(
                f"Invalid data agreement context decorator message type: {data_agreement_context_decorator.message_type}")

        if data_agreement_context_decorator.message_type == "protocol":

            if DATA_AGREEMENT_NEGOTIATION_OFFER in data_agreement_context_decorator.message["@type"]:
                data_agreement_negotiation_offer_message: DataAgreementNegotiationOfferMessage = DataAgreementNegotiationOfferMessageSchema(
                ).load(data_agreement_context_decorator.message)

                return data_agreement_negotiation_offer_message
            elif DATA_AGREEMENT_NEGOTIATION_ACCEPT in data_agreement_context_decorator.message["@type"]:
                data_agreement_negotiation_accept_message: DataAgreementNegotiationAcceptMessage = DataAgreementNegotiationAcceptMessageSchema(
                ).load(data_agreement_context_decorator.message)

                return data_agreement_negotiation_accept_message

        if data_agreement_context_decorator.message_type == "non-protocol":
            # TODO: Implement non-protocol data agreement context decorator
            pass

        return None

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

    async def construct_data_agreement_negotiation_accept_message(self, *, data_agreement_negotiation_offer_body: DataAgreementNegotiationOfferBody, connection_record: ConnectionRecord) -> typing.Tuple[DataAgreementInstance, DataAgreementNegotiationAcceptMessage]:
        """Construct data agreement negotiation accept message"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        try:
            # from_did
            pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
            from_did = DIDMyData.from_public_key_b58(
                pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

            # to_did
            to_did = DIDMyData.from_public_key_b58(
                connection_record.their_did, key_type=KeyType.ED25519)
        except StorageError as err:
            raise ADAManagerError(
                f"Failed to construct data agreement negotiation accept message: {err}"
            )

        # Data agreement offer instance
        data_agreement_offer_instance = data_agreement_negotiation_offer_body

        # Update data agreement offer instance with accept event
        data_agreement_accept_event = DataAgreementEvent(
            event_id=f"{from_did.did}#2",
            time_stamp=current_datetime_in_iso8601(),
            did=from_did.did,
            state=DataAgreementEvent.STATE_ACCEPT
        )
        data_agreement_offer_instance.event.append(
            data_agreement_accept_event
        )

        # Sign data agreement offer instance
        data_agreement_offer_instance_dict = data_agreement_offer_instance.serialize()

        signature_options = {
            "id": f"{from_did.did}#2",
            "type": "Ed25519Signature2018",
            "created": current_datetime_in_iso8601(),
            "verificationMethod": f"{from_did.did}",
            "proofPurpose": "contractAgreement",
        }

        # Generate proofs
        document_with_proof: dict = await sign_data_agreement(
            data_agreement_offer_instance_dict.copy(
            ), signature_options, from_did.public_key_b58, wallet
        )

        # Data agreement offer proof
        data_agreement_offer_proof: DataAgreementProof = DataAgreementProofSchema().load(
            document_with_proof.get("proofChain")[0])

        # Data agreement accept proof
        data_agreement_accept_proof: DataAgreementProof = DataAgreementProofSchema().load(
            document_with_proof.get("proofChain")[1])

        # Construct data agreement instance
        data_agreement_instance = DataAgreementInstance(
            context=[
                DATA_AGREEMENT_V1_SCHEMA_CONTEXT,
                ED25519_2018_CONTEXT_URL
            ],
            data_agreement_id=data_agreement_offer_instance.data_agreement_id,
            data_agreement_version=data_agreement_offer_instance.data_agreement_version,
            data_agreement_template_id=data_agreement_offer_instance.data_agreement_template_id,
            data_agreement_template_version=data_agreement_offer_instance.data_agreement_template_version,
            pii_controller_name=data_agreement_offer_instance.pii_controller_name,
            pii_controller_url=data_agreement_offer_instance.pii_controller_url,
            usage_purpose=data_agreement_offer_instance.usage_purpose,
            usage_purpose_description=data_agreement_offer_instance.usage_purpose_description,
            legal_basis=data_agreement_offer_instance.legal_basis,
            method_of_use=data_agreement_offer_instance.method_of_use,
            principle_did=data_agreement_offer_instance.principle_did,
            data_policy=data_agreement_offer_instance.data_policy,
            personal_data=data_agreement_offer_instance.personal_data,
            dpia=data_agreement_offer_instance.dpia,
            event=[
                data_agreement_offer_instance.event[0],
                data_agreement_accept_event
            ],
            proof_chain=[
                data_agreement_offer_proof,
                data_agreement_accept_proof
            ]
        )

        # Construct data agreement accept message
        data_agreement_accept_message = DataAgreementNegotiationAcceptMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=DataAgreementNegotiationAcceptBody(
                data_agreement_id=data_agreement_offer_instance.data_agreement_id,
                event=data_agreement_instance.event[1],
                proof=data_agreement_accept_proof
            )
        )

        return (data_agreement_instance, data_agreement_accept_message)

    async def construct_data_agreement_negotiation_reject_message(self,  *, data_agreement_negotiation_offer_body: DataAgreementNegotiationOfferBody, connection_record: ConnectionRecord) -> typing.Tuple[DataAgreementInstance, DataAgreementNegotiationRejectMessage]:
        """Construct data agreement negotiation reject message"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        try:
            # from_did
            pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
            from_did = DIDMyData.from_public_key_b58(
                pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

            # to_did
            to_did = DIDMyData.from_public_key_b58(
                connection_record.their_did, key_type=KeyType.ED25519)
        except StorageError as err:
            raise ADAManagerError(
                f"Failed to construct data agreement negotiation accept message: {err}"
            )

        # Data agreement offer instance
        data_agreement_offer_instance = data_agreement_negotiation_offer_body

        # Update data agreement offer instance with reject event
        data_agreement_reject_event = DataAgreementEvent(
            event_id=f"{from_did.did}#2",
            time_stamp=current_datetime_in_iso8601(),
            did=from_did.did,
            state=DataAgreementEvent.STATE_REJECT
        )

        data_agreement_offer_instance.event.append(
            data_agreement_reject_event
        )

        # Sign data agreement offer instance
        data_agreement_offer_instance_dict = data_agreement_offer_instance.serialize()

        signature_options = {
            "id": f"{from_did.did}#2",
            "type": "Ed25519Signature2018",
            "created": current_datetime_in_iso8601(),
            "verificationMethod": f"{from_did.did}",
            "proofPurpose": "contractAgreement",
        }

        # Generate proofs
        document_with_proof: dict = await sign_data_agreement(
            data_agreement_offer_instance_dict.copy(
            ), signature_options, from_did.public_key_b58, wallet
        )

        # Data agreement offer proof
        data_agreement_offer_proof: DataAgreementProof = DataAgreementProofSchema().load(
            document_with_proof.get("proofChain")[0])

        # Data agreement accept proof
        data_agreement_reject_proof: DataAgreementProof = DataAgreementProofSchema().load(
            document_with_proof.get("proofChain")[1])

        # Construct data agreement instance
        data_agreement_instance = DataAgreementInstance(
            context=[
                DATA_AGREEMENT_V1_SCHEMA_CONTEXT,
                ED25519_2018_CONTEXT_URL
            ],
            data_agreement_id=data_agreement_offer_instance.data_agreement_id,
            data_agreement_version=data_agreement_offer_instance.data_agreement_version,
            data_agreement_template_id=data_agreement_offer_instance.data_agreement_template_id,
            data_agreement_template_version=data_agreement_offer_instance.data_agreement_template_version,
            pii_controller_name=data_agreement_offer_instance.pii_controller_name,
            pii_controller_url=data_agreement_offer_instance.pii_controller_url,
            usage_purpose=data_agreement_offer_instance.usage_purpose,
            usage_purpose_description=data_agreement_offer_instance.usage_purpose_description,
            legal_basis=data_agreement_offer_instance.legal_basis,
            method_of_use=data_agreement_offer_instance.method_of_use,
            principle_did=data_agreement_offer_instance.principle_did,
            data_policy=data_agreement_offer_instance.data_policy,
            personal_data=data_agreement_offer_instance.personal_data,
            dpia=data_agreement_offer_instance.dpia,
            event=[
                data_agreement_offer_instance.event[0],
                data_agreement_reject_event
            ],
            proof_chain=[
                data_agreement_offer_proof,
                data_agreement_reject_proof
            ]
        )

        # Construct data agreement reject message

        data_agreement_reject_message = DataAgreementNegotiationRejectMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=DataAgreementNegotiationRejectBody(
                data_agreement_id=data_agreement_offer_instance.data_agreement_id,
                event=data_agreement_instance.event[1],
                proof=data_agreement_reject_proof
            )
        )

        return (data_agreement_instance, data_agreement_reject_message)

    async def construct_data_agreement_negotiation_problem_report_message(self, *, connection_record: ConnectionRecord = None, data_agreement_id: str = None, problem_code: str = None, explain: str = None) -> DataAgreementNegotiationProblemReport:
        """Construct data agreement negotiation problem report message"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        try:
            # from_did
            pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
            from_did = DIDMyData.from_public_key_b58(
                pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

            # to_did
            to_did = DIDMyData.from_public_key_b58(
                connection_record.their_did, key_type=KeyType.ED25519)
        except StorageError as err:
            raise ADAManagerError(
                f"Failed to construct data agreement negotiation problem-report message: {err}"
            )

        # Construct data agreement problem report message
        data_agreement_negotiation_problem_report = DataAgreementNegotiationProblemReport(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            problem_code=problem_code,
            explain=explain,
            data_agreement_id=data_agreement_id
        )

        return data_agreement_negotiation_problem_report

    async def send_data_agreement_negotiation_problem_report_message(self, *, connection_record: ConnectionRecord, data_agreement_negotiation_problem_report_message: DataAgreementNegotiationProblemReport) -> None:
        """Send data agreement negotiation problem report message"""

        responder: BaseResponder = await self.context.inject(BaseResponder, required=False)

        if responder:
            await responder.send(data_agreement_negotiation_problem_report_message, connection_id=connection_record.connection_id)

    async def construct_proof_presentation_request_dict_from_data_agreement_personal_data(self, *, personal_data: typing.List[dict], usage_purpose: str, usage_purpose_description: str, data_agreement_template_version: str) -> dict:
        """Construct proof presentation request dict from data agreement personal data"""

        proof_presentation_request_dict: dict = {
            "name": usage_purpose,
            "comment": usage_purpose_description,
            "version": data_agreement_template_version,
            "requested_attributes": {},
            "requested_predicates": {}
        }

        index = 1
        for personal_data_item in personal_data:
            requested_attribute = {
                "name": personal_data_item.get("attribute_name"),
                "restrictions": personal_data_item.get("restrictions")
            }
            proof_presentation_request_dict["requested_attributes"]["additionalProp" + str(
                index)] = requested_attribute
            index += 1

        return proof_presentation_request_dict

    async def construct_data_agreement_termination_terminate_message(self,  *, data_agreement_instance: DataAgreementInstance, connection_record: ConnectionRecord) -> typing.Tuple[DataAgreementInstance, DataAgreementTerminationTerminateMessage]:
        """Construct data agreement termination terminate message"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        try:
            # from_did
            pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
            from_did = DIDMyData.from_public_key_b58(
                pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

            # to_did
            to_did = DIDMyData.from_public_key_b58(
                connection_record.their_did, key_type=KeyType.ED25519)
        except StorageError as err:
            raise ADAManagerError(
                f"Failed to construct data agreement termination terminate message: {err}"
            )

        # Update data agreement instance with terminate event
        data_agreement_terminate_event = DataAgreementEvent(
            event_id=f"{from_did.did}#3",
            time_stamp=current_datetime_in_iso8601(),
            did=from_did.did,
            state=DataAgreementEvent.STATE_TERMINATE
        )

        data_agreement_instance.event.append(
            data_agreement_terminate_event
        )

        # Sign data agreement terminate instance
        data_agreement_terminate_instance_dict = data_agreement_instance.serialize()

        signature_options = {
            "id": f"{from_did.did}#3",
            "type": "Ed25519Signature2018",
            "created": current_datetime_in_iso8601(),
            "verificationMethod": f"{from_did.did}",
            "proofPurpose": "contractAgreement",
        }

        # Generate proofs
        document_with_proof: dict = await sign_data_agreement(
            data_agreement_terminate_instance_dict.copy(
            ), signature_options, from_did.public_key_b58, wallet
        )

        # Data agreement terminate proof
        data_agreement_terminate_proof: DataAgreementProof = DataAgreementProofSchema().load(
            document_with_proof.get("proofChain")[-1])

        updated_data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
            document_with_proof
        )

        # Construct data agreement reject message

        data_agreement_terminate_message = DataAgreementTerminationTerminateMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=DataAgreementTerminationTerminateBody(
                data_agreement_id=updated_data_agreement_instance.data_agreement_id,
                event=data_agreement_terminate_event,
                proof=data_agreement_terminate_proof
            )
        )

        return (updated_data_agreement_instance, data_agreement_terminate_message)

    async def query_data_agreement_instances(self, tag_query: dict = None) -> typing.List[dict]:
        """Query data agreement instances"""

        da_instance_metadata_records = await self.query_data_agreement_instance_metadata(
            tag_query=tag_query
        )

        data_agreement_instances = []

        for da_instance_metadata_record in da_instance_metadata_records:

            # Identify the method of use

            if da_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:

                try:
                    # Fetch credential exchange record
                    cred_ex_record: V10CredentialExchange = await V10CredentialExchange.retrieve_by_id(
                        self.context,
                        da_instance_metadata_record.tags.get(
                            "data_exchange_record_id")
                    )

                    if cred_ex_record.data_agreement:
                        # Load the data agreement to DataAgreementInstance
                        data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
                            cred_ex_record.data_agreement
                        )

                        # Append the data agreement instance to data_agreement_instances
                        data_agreement_instances.append({
                            "data_exchange_record_id": da_instance_metadata_record.tags.get("data_exchange_record_id"),
                            "data_agreement": data_agreement_instance.serialize(),
                            "created_at": str_to_epoch(cred_ex_record.created_at),
                            "updated_at": str_to_epoch(cred_ex_record.updated_at)
                        })

                except StorageError:
                    pass

            if da_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:
                try:
                    # Fetch presentation exchange record
                    pres_ex_record: V10PresentationExchange = await V10PresentationExchange.retrieve_by_id(
                        self.context,
                        da_instance_metadata_record.tags.get(
                            "data_exchange_record_id")
                    )

                    if pres_ex_record.data_agreement:
                        # Load the data agreement to DataAgreementInstance
                        data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
                            pres_ex_record.data_agreement
                        )

                        # Append the data agreement instance to data_agreement_instances
                        data_agreement_instances.append({
                            "data_exchange_record_id": da_instance_metadata_record.tags.get("data_exchange_record_id"),
                            "data_agreement": data_agreement_instance.serialize(),
                            "created_at": str_to_epoch(pres_ex_record.created_at),
                            "updated_at": str_to_epoch(pres_ex_record.updated_at)
                        })

                except StorageError:
                    pass

        # Sort data_agreement_instances by created_at in descending order
        data_agreement_instances = sorted(
            data_agreement_instances, key=lambda k: k['created_at'], reverse=True)

        return data_agreement_instances

    async def construct_data_agreement_qr_code_payload(self,
                                                       *,
                                                       data_agreement_id: str,
                                                       multi_use: bool = False
                                                       ) -> dict:
        """
        Construct data agreement QR code payload

        What is multi use ?

        Same QR code should be used for multiple time to share data.
        When scanned multi use QR code, it will create a single QR code record to keep track of progress.

        What is single use ?

        QR code cannot be used more than once.

        :param data_agreement_id: data agreement id
        :param mult_use: whether the QR code is for multiple use
        :return: data agreement QR code payload
        """

        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        # Fetch data agreement

        # Tag filter
        tag_filter = {
            "data_agreement_id": data_agreement_id,
            "publish_flag": "true",
            "delete_flag": "false",
        }

        try:

            # Query for the data agreement record by id
            data_agreement_record: DataAgreementV1Record = await DataAgreementV1Record.retrieve_by_tag_filter(
                self.context,
                tag_filter=tag_filter
            )

        except StorageError as err:
            raise ADAManagerError(
                f"Failed to construct data agreement qr code payload: {err}"
            )

        # Check method of use

        if data_agreement_record.method_of_use != DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:
            raise ADAManagerError(
                f"Failed to construct data agreement qr code payload: "
                f"data agreement record method-of-use is not data using service"
            )

        # QR code identifier in uuid4
        qr_code_identifier = str(uuid.uuid1())

        # Create a connection invitation

        try:
            (connection, invitation) = await self.create_invitation(
                auto_accept=True, public=False, multi_use=True, alias="DA_" + data_agreement_id + "_QR_" + qr_code_identifier
            )

        except (ConnectionManagerError, BaseModelError) as err:
            raise ADAManagerError(
                f"Failed to construct data agreement qr code payload: {err}"
            )

        # Create qr code metddata

        qr_code_metadata_record = StorageRecord(
            self.RECORD_TYPE_DATA_AGREEMENT_QR_CODE_METADATA,
            qr_code_identifier,
            {
                "data_agreement_id": data_agreement_id,
                "connection_id": connection.connection_id,
                "qr_id": qr_code_identifier,
                "multi_use": str(multi_use),
                "is_scanned": str(False)
            }
        )

        await storage.add_record(qr_code_metadata_record)

        result = {
            "qr_id": qr_code_identifier,
            "invitation": invitation.serialize()
        }

        return result

    async def query_data_agreement_qr_metadata_records(self, *, query_string: dict) -> typing.Union[typing.List[dict], None]:
        """
        Query data agreement QR code metadata records

        :param query_string: query string

        {
            "qr_id" -> qr code identifier (optional)
        }

        if query string is empty, all records will be returned.

        :return: data agreement QR code metdata records
        """

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        # Fetch qr code metadata records.
        qr_code_metadata_records = await storage.search_records(
            type_filter=self.RECORD_TYPE_DATA_AGREEMENT_QR_CODE_METADATA,
            tag_query=query_string
        ).fetch_all()

        results = []
        if qr_code_metadata_records:
            for qr_code_metadata_record in qr_code_metadata_records:
                results.append({
                    "qr_id": qr_code_metadata_record.tags.get("qr_id"),
                    "connection_id": qr_code_metadata_record.tags.get("connection_id"),
                    "data_agreement_id": qr_code_metadata_record.tags.get("data_agreement_id"),
                    "multi_use": eval(qr_code_metadata_record.tags.get("multi_use")),
                    "is_scanned": eval(qr_code_metadata_record.tags.get("is_scanned")),
                    "data_exchange_record_id":  qr_code_metadata_record.tags.get("data_exchange_record_id") if qr_code_metadata_record.tags.get("data_exchange_record_id") else "",
                })

        return results

    async def delete_data_agreement_qr_metadata_record(self, *, data_agreement_id: str, qr_id: str) -> None:
        """Delete data agreement QR code metadata record"""

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        tag_query = {
            "data_agreement_id": data_agreement_id,
            "qr_id": qr_id
        }

        # Fetch qr code metadata records.
        qr_code_metadata_records = await storage.search_records(
            type_filter=self.RECORD_TYPE_DATA_AGREEMENT_QR_CODE_METADATA,
            tag_query=tag_query
        ).fetch_all()

        # Delete qr code metadata records.
        for qr_code_metadata_record in qr_code_metadata_records:
            await storage.delete_record(qr_code_metadata_record)

    async def base64_encode_data_agreement_qr_code_payload(self, *, data_agreement_id: str, qr_id: str) -> str:
        """Base64 encode data agreement QR code payload"""

        # Storage instance from context

        storage: BaseStorage = await self.context.inject(BaseStorage)

        tag_query = {
            "data_agreement_id": data_agreement_id,
            "qr_id": qr_id
        }

        try:

            # Fetch qr code metadata record.
            qr_code_metadata_record = await storage.search_records(
                type_filter=self.RECORD_TYPE_DATA_AGREEMENT_QR_CODE_METADATA,
                tag_query=tag_query
            ).fetch_single()

            # Fetch connection record by connection id

            connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
                self.context,
                qr_code_metadata_record.tags.get("connection_id")
            )

            # Fetch connection invitation

            connection_invitation: ConnectionInvitation = await connection_record.retrieve_invitation(
                self.context
            )

        except StorageError as err:
            raise ADAManagerError(
                f"Failed to base64 encode data agreement qr code payload: {err}"
            )

        qr_payload = {
            "qr_id": qr_id,
            "invitation": connection_invitation.serialize(),
        }

        # Encode payload to base64

        qr_payload_base64 = base64.b64encode(
            json.dumps(qr_payload).encode('UTF-8'))

        return qr_payload_base64.decode('UTF-8')

    async def process_data_agreement_qr_code_initiate_message(self, data_agreement_qr_code_initiate_message: DataAgreementQrCodeInitiateMessage, receipt: MessageReceipt) -> None:
        """
        Process data agreement qr code initiate message.
        """

        # Storage instance from context

        storage: BaseStorage = await self.context.inject(BaseStorage)

        # Responder instance
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        # From and To DIDs for the response messages
        response_message_from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)
        response_message_to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)

        # Query qr code metadata records by qr_id

        try:
            qr_code_metadata_record = await storage.search_records(
                type_filter=self.RECORD_TYPE_DATA_AGREEMENT_QR_CODE_METADATA,
                tag_query={
                    "qr_id": data_agreement_qr_code_initiate_message.body.qr_id}
            ).fetch_single()
        except StorageError as err:
            # if not found send problem-report
            problem_report = DataAgreementQrCodeProblemReport(
                problem_code=DataAgreementQrCodeProblemReportReason.INVALID_QR_ID.value,
                explain=f"Failed to query data agreement qr code metadata records: {err}",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=round(time.time() * 1000),
                qr_id=data_agreement_qr_code_initiate_message.body.qr_id,
            )

            if responder:
                await responder.send_reply(problem_report, connection_id=self.context.connection_record.connection_id)

            raise ADAManagerError(
                f"Failed to query data agreement qr code metadata records: {err}"
            )

        # multi_use flag
        multi_use = eval(qr_code_metadata_record.tags.get("multi_use"))

        # is_scanned flag
        is_scanned = eval(qr_code_metadata_record.tags.get("is_scanned"))

        if multi_use:
            # Create a copy of qr code metadata record, with new record identifier and then continue processing

            # QR code identifier in uuid4
            qr_code_identifier = str(uuid.uuid1())

            qr_code_metadata_record = StorageRecord(
                self.RECORD_TYPE_DATA_AGREEMENT_QR_CODE_METADATA,
                qr_code_identifier,
                {
                    "data_agreement_id": qr_code_metadata_record.tags.get("data_agreement_id"),
                    "connection_id": self.context.connection_record.connection_id,
                    "qr_id": qr_code_identifier,
                    "multi_use": str(qr_code_metadata_record.tags.get("multi_use")),
                    "is_scanned": str(True)
                }
            )

            await storage.add_record(qr_code_metadata_record)
        else:
            if is_scanned:
                # if is_multi_use is False and is_scanned is True,
                # send problem-report (QR code already scanned)

                problem_report = DataAgreementQrCodeProblemReport(
                    problem_code=DataAgreementQrCodeProblemReportReason.QR_CODE_SCANNED_ONCE.value,
                    explain=f"QR code cannot be scanned more than once.",
                    from_did=response_message_from_did.did,
                    to_did=response_message_to_did.did,
                    created_time=round(time.time() * 1000),
                    qr_id=data_agreement_qr_code_initiate_message.body.qr_id,
                )

                if responder:
                    await responder.send_reply(problem_report, connection_id=self.context.connection_record.connection_id)

                raise ADAManagerError(
                    f"QR code already scanned"
                )

        # If found, fetch the corresponding data agreement record
        # Check if method-of-use is data-using-service else send problem-report

        # Fetch data agreement

        # Tag filter
        tag_filter = {
            "data_agreement_id": qr_code_metadata_record.tags.get("data_agreement_id"),
            "publish_flag": "true",
            "delete_flag": "false",
        }

        try:

            # Query for the old data agreement record by id
            data_agreement_record: DataAgreementV1Record = await DataAgreementV1Record.retrieve_by_tag_filter(
                self.context,
                tag_filter=tag_filter
            )

            # Check if data agreement method-of-use is data-using-service
            if data_agreement_record.method_of_use != DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:

                problem_report = DataAgreementQrCodeProblemReport(
                    problem_code=DataAgreementQrCodeProblemReportReason.FAILED_TO_PROCESS_QR_CODE_INITIATE_MESSAGE.value,
                    explain=f"Data agreement method-of-use is not data-using-service.",
                    from_did=response_message_from_did.did,
                    to_did=response_message_to_did.did,
                    created_time=round(time.time() * 1000),
                    qr_id=data_agreement_qr_code_initiate_message.body.qr_id,
                )

                if responder:
                    await responder.send_reply(problem_report, connection_id=self.context.connection_record.connection_id)

                raise ADAManagerError(
                    f"Data agreement method-of-use must be {DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE}"
                )

            # Create presentation-request message from the stored presentation request dict

            # Update qr code metadata record with
            #   is_scanned = True,
            #   data_exchange_record identifier,
            #   update connection_id

            # Construct presentation request message.

            indy_proof_request = data_agreement_record.data_agreement_proof_presentation_request
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

            presentation_manager = PresentationManager(self.context)
            pres_ex_record = None
            try:
                (pres_ex_record) = await presentation_manager.create_exchange_for_request(
                    connection_id=self.context.connection_record.connection_id,
                    presentation_request_message=presentation_request_message,
                )
                result = pres_ex_record.serialize()
            except (BaseModelError, StorageError) as err:
                raise ADAManagerError(
                    f"Failed to create presentation exchange record: {err}"
                )

            # Construct data agreement offer message.
            data_agreement_offer_message = await self.construct_data_agreement_offer_message(
                connection_record=self.context.connection_record,
                data_agreement_template_record=data_agreement_record,
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
            await pres_ex_record.save(self.context)

            # Save data agreement instance metadata
            await self.store_data_agreement_instance_metadata(
                data_agreement_id=data_agreement_offer_message.body.data_agreement_id,
                data_agreement_template_id=data_agreement_offer_message.body.data_agreement_template_id,
                data_exchange_record_id=pres_ex_record.presentation_exchange_id,
                method_of_use=data_agreement_offer_message.body.method_of_use
            )

            result = pres_ex_record.serialize()

            # Send presentation request message to connection

            if responder:
                await responder.send_reply(presentation_request_message, connection_id=self.context.connection_record.connection_id)

            # Update qr code metadata record with new tags
            qr_code_metadata_record_tags = qr_code_metadata_record.tags
            qr_code_metadata_record_tags["is_scanned"] = str(True)
            qr_code_metadata_record_tags["connection_id"] = self.context.connection_record.connection_id
            qr_code_metadata_record_tags["data_exchange_record_id"] = pres_ex_record.presentation_exchange_id
            await storage.update_record_tags(qr_code_metadata_record, qr_code_metadata_record_tags)

        except StorageError as err:
            problem_report = DataAgreementQrCodeProblemReport(
                problem_code=DataAgreementQrCodeProblemReportReason.FAILED_TO_PROCESS_QR_CODE_INITIATE_MESSAGE.value,
                explain=f"Failed to process Data Agreement Qr code initiate message: {err}",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=round(time.time() * 1000),
                qr_id=data_agreement_qr_code_initiate_message.body.qr_id,
            )

            if responder:
                await responder.send_reply(problem_report, connection_id=self.context.connection_record.connection_id)

            raise ADAManagerError(
                f"Failed to process Data Agreement Qr code initiate message: {err}"
            )

    async def send_data_agreement_qr_code_workflow_initiate_message(self, *, qr_id: str, connection_id: str) -> None:
        # Storage instance from context

        storage: BaseStorage = await self.context.inject(BaseStorage)

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

        # Construct Data Agreement Qr Code Workflow Initiate Message

        data_agreement_qr_code_workflow_initiate_message = DataAgreementQrCodeInitiateMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=DataAgreementQrCodeInitiateBody(
                qr_id=qr_id,
            )
        )

        # Send Data Agreement Qr Code Workflow Initiate Message to connection
        if responder:
            await responder.send(data_agreement_qr_code_workflow_initiate_message, connection_id=connection_record.connection_id)

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

    async def generate_firebase_dynamic_link_for_data_agreement_qr_payload(self, *, data_agreement_id: str, qr_id: str) -> str:
        """Fn to generate firebase dynamic link for data agreement qr payload"""

        # Fetch config from os environ
        config = await self.fetch_firebase_config_from_os_environ()

        # Obtain base64 encoded qr code payload
        base64_qr_payload = await self.base64_encode_data_agreement_qr_code_payload(
            data_agreement_id=data_agreement_id,
            qr_id=qr_id
        )

        # Generate firebase dynamic link
        # qt stands for qr code type
        # qp stands for qr code payload
        payload_link = self.context.settings.get(
            "default_endpoint") + "?qt=2&qp=" + base64_qr_payload

        # Construct firebase payload
        payload = {
            "dynamicLinkInfo": {
                "domainUriPrefix": config["firebase_domain_uri_prefix"],
                "link": payload_link,
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
                        f"Failed to generate firebase dynamic link for data agreement qr payload: {resp.status} {tresp}"
                    )

        return jresp["shortLink"]

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

    async def create_invitation(
        self,
        my_label: str = None,
        my_endpoint: str = None,
        their_role: str = None,
        auto_accept: bool = None,
        public: bool = False,
        multi_use: bool = False,
        alias: str = None,
    ) -> typing.Tuple[ConnectionRecord, ConnectionInvitation]:
        """
        Generate new connection invitation.

        This interaction represents an out-of-band communication channel. In the future
        and in practice, these sort of invitations will be received over any number of
        channels such as SMS, Email, QR Code, NFC, etc.

        Structure of an invite message:

        ::

            {
                "@type": "https://didcomm.org/connections/1.0/invitation",
                "label": "Alice",
                "did": "did:sov:QmWbsNYhMrjHiqZDTUTEJs"
            }

        Or, in the case of a peer DID:

        ::

            {
                "@type": "https://didcomm.org/connections/1.0/invitation",
                "label": "Alice",
                "did": "did:peer:oiSqsNYhMrjHiqZDTUthsw",
                "recipientKeys": ["8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"],
                "serviceEndpoint": "https://example.com/endpoint"
            }

        Currently, only peer DID is supported.

        Args:
            my_label: label for this connection
            my_endpoint: endpoint where other party can reach me
            their_role: a role to assign the connection
            auto_accept: auto-accept a corresponding connection request
                (None to use config)
            public: set to create an invitation from the public DID
            multi_use: set to True to create an invitation for multiple use
            alias: optional alias to apply to connection for later use

        Returns:
            A tuple of the new `ConnectionRecord` and `ConnectionInvitation` instances

        """
        if not my_label:
            my_label = self.context.settings.get("default_label")

        image_url = None

        try:
            # Fetch iGrant.io config
            igrantio_config = await self.fetch_igrantio_config_from_os_environ()

            # Construct iGrant.io organisation detail endpoint URL
            igrantio_organisation_detail_url = f"{igrantio_config['igrantio_endpoint_url']}/v1/organizations/{igrantio_config['igrantio_org_id']}"

            # Construct request headers
            request_headers = {
                "Authorization": f"ApiKey {igrantio_config['igrantio_org_api_key']}"
            }

            # Make request to iGrant.io organisation detail endpoint
            async with aiohttp.ClientSession(headers=request_headers) as session:
                async with session.get(igrantio_organisation_detail_url) as resp:
                    if resp.status == 200:
                        jresp = await resp.json()

                        if "Organization" in jresp:
                            organization_details = jresp["Organization"]
                            my_label = organization_details["Name"]
                            image_url = organization_details["LogoImageURL"] + "/web"

        except ADAManagerError as err:
            pass

        wallet: BaseWallet = await self.context.inject(BaseWallet)

        if public:
            if not self.context.settings.get("public_invites"):
                raise ConnectionManagerError(
                    "Public invitations are not enabled")

            public_did = await wallet.get_public_did()
            if not public_did:
                raise ConnectionManagerError(
                    "Cannot create public invitation with no public DID"
                )

            if multi_use:
                raise ConnectionManagerError(
                    "Cannot use public and multi_use at the same time"
                )

            # FIXME - allow ledger instance to format public DID with prefix?
            invitation = ConnectionInvitation(
                label=my_label, did=f"did:sov:{public_did.did}", image_url=image_url
            )
            return None, invitation

        invitation_mode = ConnectionRecord.INVITATION_MODE_ONCE
        if multi_use:
            invitation_mode = ConnectionRecord.INVITATION_MODE_MULTI

        if not my_endpoint:
            my_endpoint = self.context.settings.get("default_endpoint")
        accept = (
            ConnectionRecord.ACCEPT_AUTO
            if (
                auto_accept
                or (
                    auto_accept is None
                    and self.context.settings.get("debug.auto_accept_requests")
                )
            )
            else ConnectionRecord.ACCEPT_MANUAL
        )

        # Create and store new invitation key
        connection_key = await wallet.create_signing_key()

        # Create connection record
        connection = ConnectionRecord(
            initiator=ConnectionRecord.INITIATOR_SELF,
            invitation_key=connection_key.verkey,
            their_role=their_role,
            state=ConnectionRecord.STATE_INVITATION,
            accept=accept,
            invitation_mode=invitation_mode,
            alias=alias,
        )

        await connection.save(self.context, reason="Created new invitation")

        # Create connection invitation message
        # Note: Need to split this into two stages to support inbound routing of invites
        # Would want to reuse create_did_document and convert the result
        invitation = ConnectionInvitation(
            label=my_label, recipient_keys=[
                connection_key.verkey], endpoint=my_endpoint, image_url=image_url
        )
        await connection.attach_invitation(self.context, invitation)

        return connection, invitation

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

    async def create_or_update_data_controller_details_in_wallet(self) -> StorageRecord:
        """Create or update data controller details in wallet."""

        # Storage instance
        storage: IndyStorage = await self.context.inject(BaseStorage)

        result = json.dumps({})

        # Retrieve data controller details from storage
        try:

            storage_record: StorageRecord = await storage.search_records(
                self.RECORD_TYPE_DATA_CONTROLLER_DETAILS
            ).fetch_single()

            data_controller = await self.fetch_org_details_from_igrantio()

            await storage.update_record_value(storage_record, data_controller)

            return data_controller

        except StorageError as err:

            try:
                data_controller = await self.fetch_org_details_from_igrantio()

                # Create data controller details record
                storage_record = StorageRecord(
                    self.RECORD_TYPE_DATA_CONTROLLER_DETAILS,
                    data_controller,
                )

                await storage.add_record(storage_record)

                return data_controller
            except ADAManagerError as err:
                # Create data controller details record
                storage_record = StorageRecord(
                    self.RECORD_TYPE_DATA_CONTROLLER_DETAILS,
                    result,
                )

                await storage.add_record(storage_record)

                return result

        except ADAManagerError as err:
            pass

        return result

    async def process_data_controller_details_message(self, data_controller_details_message: DataControllerDetailsMessage, receipt: MessageReceipt) -> None:
        """
        Process data controller details message.
        """

        # Responder instance
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        # From and To MyData DIDs
        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)
        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)

        # Query data_controller_details record
        data_controller_details: str = await self.create_or_update_data_controller_details_in_wallet()

        # Construct Data Controller model class
        data_controller: DataController = DataControllerSchema().load(
            json.loads(data_controller_details))

        # Construct DataControllerDetailsResponseMessage
        data_controller_details_response_message = DataControllerDetailsResponseMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=data_controller
        )

        # Send DataControllerDetailsResponseMessage to the requester.

        if responder:
            await responder.send_reply(data_controller_details_response_message)

    async def send_data_controller_details_message(self, conn_id: str) -> None:
        """Send data controller details message."""

        # Responder instance
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        try:

            # Retrieve connection record by id
            connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(
                self.context,
                conn_id
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

        # Construct DataControllerDetailsMessage Message
        data_controller_details_message = DataControllerDetailsMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000)
        )

        # Send message
        if responder:
            await responder.send_reply(data_controller_details_message, connection_id=connection_record.connection_id)

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
            await responder.send_reply(existing_connections_message, connection_id=connection_record.connection_id)

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
