import datetime
import logging
import json
import time
import uuid
import typing

from asyncio import shield
from aries_cloudagent.connections.models.connection_target import ConnectionTarget
from c14n.Canonicalize import serialize
import semver
import aiohttp

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.responder import BaseResponder
from aries_cloudagent.messaging.credential_definitions.util import CRED_DEF_SENT_RECORD_TYPE
from aries_cloudagent.core.dispatcher import DispatcherResponder
from aries_cloudagent.transport.inbound.receipt import MessageReceipt
from aries_cloudagent.core.error import BaseError
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.indy import IndyStorage
from aries_cloudagent.storage.error import StorageNotFoundError, StorageSearchError, StorageDuplicateError, StorageError
from aries_cloudagent.wallet.indy import IndyWallet
from aries_cloudagent.wallet.base import BaseWallet, DIDInfo
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager
from aries_cloudagent.ledger.base import BaseLedger
from aries_cloudagent.ledger.error import LedgerError
from aries_cloudagent.issuer.base import BaseIssuer, IssuerError
from aries_cloudagent.messaging.decorators.default import DecoratorSet
from aries_cloudagent.transport.pack_format import PackWireFormat
from aries_cloudagent.transport.wire_format import BaseWireFormat
from aries_cloudagent.messaging.decorators.transport_decorator import TransportDecorator, TransportDecoratorSchema
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager, ConnectionManagerError

from .messages.create_did import CreateDIDMessage
from .messages.read_did import ReadDIDMessage, ReadDIDMessageBody
from .messages.read_did_response import ReadDIDResponseMessage, ReadDIDResponseMessageSchema
from .messages.delete_did import DeleteDIDMessage, DeleteDIDMessageBody
from .messages.delete_did_response import DeleteDIDResponseMessage, DeleteDIDResponseMessageBody
from .messages.create_did_response import CreateDIDResponseMessage
from .messages.problem_report import (
    MyDataDIDProblemReportMessage,
    MyDataDIDProblemReportMessageReason,
    DataAgreementNegotiationProblemReport,
    DataAgreementProblemReport,
    DataAgreementProblemReportReason
)
from .messages.read_data_agreement import ReadDataAgreement
from .messages.read_data_agreement_response import ReadDataAgreementResponse
from .messages.data_agreement_offer import DataAgreementNegotiationOfferMessage, DataAgreementNegotiationOfferMessageSchema
from .messages.data_agreement_accept import DataAgreementNegotiationAcceptMessage, DataAgreementNegotiationAcceptMessageSchema
from .messages.data_agreement_reject import DataAgreementNegotiationRejectMessage, DataAgreementNegotiationRejectMessageSchema
from .messages.data_agreement_terminate import DataAgreementTerminationTerminateMessage, DataAgreementTerminationTerminateMessageSchema
from .messages.data_agreement_verify import DataAgreementVerify

from .models.data_agreement_model import DATA_AGREEMENT_V1_SCHEMA_CONTEXT, DataAgreementEventSchema, DataAgreementV1, DataAgreementPersonalData, DataAgreementV1Schema
from .models.read_data_agreement_model import ReadDataAgreementBody
from .models.diddoc_model import MyDataDIDBody, MyDataDIDResponseBody, MyDataDIDDoc, MyDataDIDDocService, MyDataDIDDocVerificationMethod, MyDataDIDDocAuthentication
from .models.read_data_agreement_response_model import ReadDataAgreementResponseBody
from .models.exchange_records.mydata_did_registry_didcomm_transaction_record import MyDataDIDRegistryDIDCommTransactionRecord
from .models.exchange_records.data_agreement_didcomm_transaction_record import DataAgreementCRUDDIDCommTransaction
from .models.exchange_records.data_agreement_record import DataAgreementV1Record
from .models.exchange_records.data_agreement_personal_data_record import DataAgreementPersonalDataRecord
from .models.data_agreement_negotiation_offer_model import DataAgreementNegotiationOfferBody, DataAgreementEvent, DataAgreementProof, DataAgreementProofSchema
from .models.data_agreement_instance_model import DataAgreementInstance, DataAgreementInstanceSchema
from .models.data_agreement_negotiation_accept_model import DataAgreementNegotiationAcceptBody, DataAgreementNegotiationAcceptBodySchema
from .models.data_agreement_negotiation_reject_model import DataAgreementNegotiationRejectBody, DataAgreementNegotiationRejectBodySchema
from .models.data_agreement_termination_terminate_model import DataAgreementTerminationTerminateBody, DataAgreementTerminationTerminateBodySchema
from .models.data_agreement_verify_model import DataAgreementVerifyBody, DataAgreementVerifyBodySchema

from .utils.diddoc import DIDDoc
from .utils.did.mydata_did import DIDMyData
from .utils.wallet.key_type import KeyType
from .utils.verification_method import PublicKeyType
from .utils.jsonld import ED25519_2018_CONTEXT_URL
from .utils.jsonld.data_agreement import sign_data_agreement
from .utils.util import current_datetime_in_iso8601

from .decorators.data_agreement_context_decorator import DataAgreementContextDecoratorSchema, DataAgreementContextDecorator
from .message_types import (
    DATA_AGREEMENT_NEGOTIATION_OFFER,
    DATA_AGREEMENT_NEGOTIATION_ACCEPT,
    READ_DATA_AGREEMENT
)

from ..patched_protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange
)
from ..patched_protocols.present_proof.v1_0.models.presentation_exchange import (
    V10PresentationExchange
)


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

    DATA_AGREEMENT_RECORD_TYPE = "dataagreement_record"

    def __init__(self, context: InjectionContext) -> None:
        self._context = context
        self._logger = logging.getLogger(__name__)

    @property
    def context(self) -> InjectionContext:
        return self._context

    async def process_mydata_did_problem_report_message(self, mydata_did_problem_report: MyDataDIDProblemReportMessage, receipt: MessageReceipt):
        """
        Process problem report DIDComm message for MyData DID protocol.
        """
        # Thread identifier
        thread_id = mydata_did_problem_report._thread_id

        mydata_did_registry_didcomm_transaction_record = None
        try:

            # Fetch MyData DID registry didcomm transaction record
            mydata_did_registry_didcomm_transaction_record: MyDataDIDRegistryDIDCommTransactionRecord = await MyDataDIDRegistryDIDCommTransactionRecord.retrieve_by_tag_filter(
                context=self.context,
                tag_filter={"thread_id": thread_id}
            )

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # No record found
            self._logger.debug(
                "Failed to process mydata-did/1.0/problem-report message; "
                "No MyData DID registry didcomm transaction record found for thread_id: %s", thread_id
            )
            return

        # Assert transaction record is not None
        assert mydata_did_registry_didcomm_transaction_record is not None

        mydata_did_registry_didcomm_transaction_record.messages_list.append(
            mydata_did_problem_report.to_json()
        )

        # Update transaction record
        await mydata_did_registry_didcomm_transaction_record.save(self.context)

    async def process_create_did_response_message(self, create_did_response_message: CreateDIDResponseMessage, receipt: MessageReceipt):
        """
        Process create-did-response DIDComm message
        """

        # Storage instance
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Thread identifier
        thread_id = create_did_response_message._thread_id

        mydata_did_registry_didcomm_transaction_record = None
        try:

            # Fetch MyData DID registry didcomm transaction record
            mydata_did_registry_didcomm_transaction_record: MyDataDIDRegistryDIDCommTransactionRecord = await MyDataDIDRegistryDIDCommTransactionRecord.retrieve_by_tag_filter(
                context=self.context,
                tag_filter={"thread_id": thread_id}
            )

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # No record found
            self._logger.debug(
                "Failed to process create-did-response message; "
                "No MyData DID registry didcomm transaction record found for thread_id: %s", thread_id
            )
            return

        # Assert transaction record is not None
        assert mydata_did_registry_didcomm_transaction_record is not None

        mydata_did_registry_didcomm_transaction_record.messages_list.append(
            create_did_response_message.to_json()
        )

        # Update transaction record
        await mydata_did_registry_didcomm_transaction_record.save(self.context)

        # Mark MyData DID as remote i.e. registered in the DID registry
        mydata_did_remote_record = StorageRecord(
            type=self.RECORD_TYPE_MYDATA_DID_REMOTE,
            value=create_did_response_message.body.did_doc.to_json(),
            tags={
                "did": create_did_response_message.body.did_doc.diddoc_id,
                "sov_verkey": DIDMyData.from_did(create_did_response_message.body.did_doc.diddoc_id).public_key_b58,
                "status": "active"
            }
        )

        # Save record
        await storage.add_record(mydata_did_remote_record)

    async def process_create_did_message(self, create_did_message: CreateDIDMessage, receipt: MessageReceipt):
        """
        Process create-did DIDComm message
        """

        # Storage instance
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Wallet instance
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Responder instance
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
            # Check if DID is already registered
            mydata_did_registry_did_info_record = await storage.search_records(
                type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REGISTRY_DID_INFO,
                tag_query={"did": create_did_message.body.diddoc_id}
            ).fetch_single()

            # Send problem-report message.
            mydata_did_problem_report = MyDataDIDProblemReportMessage(
                problem_code=MyDataDIDProblemReportMessageReason.DID_EXISTS,
                explain="DID already registered in the DID registry",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=str(int(datetime.datetime.utcnow().timestamp()))
            )

            # Assign thread id
            mydata_did_problem_report.assign_thread_id(
                thid=create_did_message._id)

            if responder:
                await responder.send_reply(mydata_did_problem_report, connection_id=self.context.connection_record.connection_id)

            return
        except (StorageNotFoundError, StorageDuplicateError) as e:
            pass

        try:

            # Validate the ownership of the did by verifying the signature
            await create_did_message.verify_signed_field(
                field_name="body",
                wallet=wallet,
                signer_verkey=DIDMyData.from_did(
                    create_did_message.body.diddoc_id).public_key_b58
            )
        except BaseModelError as e:
            self._logger.error(
                f"Create DID message signature validation failed: {e}")

            # Send problem-report message.
            mydata_did_problem_report = MyDataDIDProblemReportMessage(
                problem_code=MyDataDIDProblemReportMessageReason.MESSAGE_BODY_SIGNATURE_VERIFICATION_FAILED,
                explain="DID document signature verification failed",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=str(int(datetime.datetime.utcnow().timestamp()))
            )

            # Assign thread id
            mydata_did_problem_report.assign_thread_id(
                thid=create_did_message._id)

            if responder:
                await responder.send_reply(mydata_did_problem_report, connection_id=self.context.connection_record.connection_id)

            return

        # Create a record for the registered DID
        mydata_did_registry_did_info_record_tags = {
            "did": create_did_message.body.diddoc_id,
            "connection_id": self.context.connection_record.connection_id,
            "version": "1",
            "status": "active"
        }

        mydata_did_registry_did_info_record = StorageRecord(
            type=ADAManager.RECORD_TYPE_MYDATA_DID_REGISTRY_DID_INFO,
            value=create_did_message.body.to_json(),
            tags=mydata_did_registry_did_info_record_tags
        )

        await storage.add_record(mydata_did_registry_did_info_record)

        # Send create-did-response message
        create_did_response_message = CreateDIDResponseMessage(
            from_did=response_message_from_did.did,
            to_did=response_message_to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
            body=MyDataDIDResponseBody(
                did_doc=create_did_message.body,
                version=mydata_did_registry_did_info_record_tags.get(
                    "version"),
                status=mydata_did_registry_did_info_record_tags.get("status")
            )
        )

        # Assign thread id
        create_did_response_message.assign_thread_id(
            thid=create_did_message._id)

        # Create transaction record to keep track of didcomm messages
        transaction_record = MyDataDIDRegistryDIDCommTransactionRecord(
            thread_id=create_did_message._id,
            message_type=MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_CREATE_DID,
            messages_list=[create_did_message.to_json(
            ), create_did_response_message.to_json()],
            connection_id=self.context.connection_record.connection_id,
        )

        # Save transaction record
        await transaction_record.save(self.context)

        if responder:
            await responder.send_reply(create_did_response_message, connection_id=self.context.connection_record.connection_id)

    async def fetch_mydata_did_registry_connection_record(self) -> typing.Tuple[typing.Union[ConnectionRecord, None], typing.Union[None, Exception]]:
        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        mydata_did_registry_connection_record = None

        try:

            # Search for existing connection_id marked as MyData DID registry
            mydata_did_registry_connection_record: StorageRecord = await storage.search_records(
                self.RECORD_TYPE_MYDATA_DID_REGISTRY_CONNECTION,
            ).fetch_single()

            # MyData DID Registry connection identifier
            mydata_did_registry_connection_id = mydata_did_registry_connection_record.value

            # Fetch connection record from storage
            connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(self.context, mydata_did_registry_connection_id)

            return connection_record, None

        except (StorageError, StorageNotFoundError, StorageDuplicateError) as e:
            return None, e

    async def fetch_auditor_connection_record(self) -> typing.Tuple[typing.Union[ConnectionRecord, None], typing.Union[None, Exception]]:
        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        auditor_connection_record = None

        try:

            # Search for existing connection_id marked as Auditor
            auditor_connection_record: StorageRecord = await storage.search_records(
                self.RECORD_TYPE_AUDITOR_CONNECTION,
            ).fetch_single()

            # Auditor connection identifier
            auditor_connection_id = auditor_connection_record.value

            # Fetch connection record from storage
            connection_record: ConnectionRecord = await ConnectionRecord.retrieve_by_id(self.context, auditor_connection_id)

            return connection_record, None

        except (StorageError, StorageNotFoundError, StorageDuplicateError) as e:
            return None, e

    async def send_create_did_message(self, did: str) -> MyDataDIDRegistryDIDCommTransactionRecord:
        """
        Send create-did didcomm message to MyData DID Registry.

        Args:
            did: The did to be created.

        Returns:
            The transaction record.
        """

        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        connection_record, err = await self.fetch_mydata_did_registry_connection_record()
        if err:
            raise ADAManagerError(
                f"Failed to send create-did message. "
                f"Reason: {err}"
            )

        # from_did
        pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
        from_did = DIDMyData.from_public_key_b58(
            pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

        # to_did
        pairwise_remote_did_record = await storage.search_records(
            type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
            tag_query={"did": connection_record.their_did}
        ).fetch_single()
        to_did = DIDMyData.from_public_key_b58(
            pairwise_remote_did_record.value, key_type=KeyType.ED25519)

        # to be created did
        # Fetch local did record for verkey provided.
        local_did_record: DIDInfo = await wallet.get_local_did(did)
        mydata_did = DIDMyData.from_public_key_b58(
            local_did_record.verkey, key_type=KeyType.ED25519)

        # Create DIDDoc
        did_doc = MyDataDIDDoc(
            context=DIDDoc.CONTEXT,
            diddoc_id=mydata_did.did,
            verification_method=[
                MyDataDIDDocVerificationMethod(
                    verification_method_id=f"{mydata_did.did}#1",
                    verification_method_type=PublicKeyType.ED25519_SIG_2018.ver_type,
                    controller=mydata_did.did,
                    public_key_base58=mydata_did.fingerprint
                )
            ],
            authentication=[
                MyDataDIDDocAuthentication(
                    authentication_type=PublicKeyType.ED25519_SIG_2018.authn_type,
                    public_key=f"{mydata_did.did}#1"
                )
            ],
            service=[
                MyDataDIDDocService(
                    service_id=f"{mydata_did.did};didcomm",
                    service_type="DIDComm",
                    service_priority=0,
                    recipient_keys=[
                        mydata_did.fingerprint
                    ],
                    service_endpoint=self.context.settings.get(
                        "default_endpoint")
                )

            ],
        )

        # Create create-did message
        create_did_message = CreateDIDMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
            body=did_doc
        )

        # Sign did doc using local did verkey to prove ownership
        await create_did_message.sign_field("body", local_did_record.verkey, wallet, timestamp=time.time())

        # Create transaction record
        transaction_record = MyDataDIDRegistryDIDCommTransactionRecord(
            thread_id=create_did_message._id,
            message_type=MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_CREATE_DID,
            messages_list=[create_did_message.to_json()],
            connection_id=connection_record.connection_id,
        )

        # Save transaction record
        await transaction_record.save(self.context, reason="Sending create-did message to MyData DID Registry")

        # Send create-did message to MyData DID Registry
        responder: BaseResponder = await self.context.inject(BaseResponder, required=False)
        if responder:
            await responder.send(create_did_message, connection_id=connection_record.connection_id)

        return transaction_record

    async def process_read_did_message(self, read_did_message: ReadDIDMessage, receipt: MessageReceipt):
        """
        Process read-did DIDComm message
        """

        # Storage instance from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

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

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # Send problem-report message.

            mydata_did_problem_report = MyDataDIDProblemReportMessage(
                problem_code=MyDataDIDProblemReportMessageReason.DID_NOT_FOUND,
                explain="DID not found.",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=str(int(datetime.datetime.utcnow().timestamp()))
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
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
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

        # Create transaction record to keep track of didcomm messages
        transaction_record = MyDataDIDRegistryDIDCommTransactionRecord(
            thread_id=read_did_message._id,
            message_type=MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_READ_DID,
            messages_list=[read_did_message.to_json(
            ), read_did_response_message.to_json()],
            connection_id=self.context.connection_record.connection_id,
        )

        # Save transaction record
        await transaction_record.save(self.context)

        if responder:
            await responder.send_reply(read_did_response_message)

    async def process_read_did_response_message(self, read_did_response_message: ReadDIDResponseMessage, receipt: MessageReceipt):
        """
        Process read-did-response DIDComm message
        """

        # Thread identifier
        thread_id = read_did_response_message._thread_id

        mydata_did_registry_didcomm_transaction_record = None
        try:

            # Fetch MyData DID registry didcomm transaction record
            mydata_did_registry_didcomm_transaction_record: MyDataDIDRegistryDIDCommTransactionRecord = await MyDataDIDRegistryDIDCommTransactionRecord.retrieve_by_tag_filter(
                context=self.context,
                tag_filter={"thread_id": thread_id}
            )

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # No record found
            self._logger.debug(
                "Failed to process read-did-response message; "
                "No MyData DID registry didcomm transaction record found for thread_id: %s", thread_id
            )
            return

        # Assert transaction record is not None
        assert mydata_did_registry_didcomm_transaction_record is not None

        mydata_did_registry_didcomm_transaction_record.messages_list.append(
            read_did_response_message.to_json()
        )

        # Update transaction record
        await mydata_did_registry_didcomm_transaction_record.save(self.context)

    async def send_read_did_message(self, did: str) -> MyDataDIDRegistryDIDCommTransactionRecord:
        """
        Send read-did DIDComm message
        """

        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        connection_record, err = await self.fetch_mydata_did_registry_connection_record()
        if err:
            raise ADAManagerError(
                f"Failed to send read-did message. "
                f"Reason: {err}"
            )

        # from_did
        pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
        from_did = DIDMyData.from_public_key_b58(
            pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

        # to_did
        pairwise_remote_did_record = await storage.search_records(
            type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
            tag_query={"did": connection_record.their_did}
        ).fetch_single()
        to_did = DIDMyData.from_public_key_b58(
            pairwise_remote_did_record.value, key_type=KeyType.ED25519)

        # Create read-did message
        read_did_message = ReadDIDMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
            body=ReadDIDMessageBody(
                did=did
            )
        )

        # Create transaction record
        transaction_record = MyDataDIDRegistryDIDCommTransactionRecord(
            thread_id=read_did_message._id,
            message_type=MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_READ_DID,
            messages_list=[read_did_message.to_json()],
            connection_id=connection_record.connection_id,
        )

        # Save transaction record
        await transaction_record.save(self.context, reason="Send read-did message")

        # Send read-did message to MyData DID Registry
        responder: BaseResponder = await self.context.inject(BaseResponder, required=False)
        if responder:
            await responder.send(read_did_message, connection_id=connection_record.connection_id)

        return transaction_record

    async def process_delete_did_message(self, delete_did_message: DeleteDIDMessage, receipt: MessageReceipt):
        """
        Process delete-did DIDComm message
        """

        # Storage instance
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Wallet instance
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Responder instance
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
                tag_query={"did": delete_did_message.body.did}
            ).fetch_single()

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # Send problem-report message.

            mydata_did_problem_report = MyDataDIDProblemReportMessage(
                problem_code=MyDataDIDProblemReportMessageReason.DID_NOT_FOUND,
                explain="DID not found.",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=str(int(datetime.datetime.utcnow().timestamp()))
            )

            # Assign thread id
            mydata_did_problem_report.assign_thread_id(
                thid=delete_did_message._id)

            if responder:
                await responder.send_reply(mydata_did_problem_report, connection_id=self.context.connection_record.connection_id)

            return

        try:

            # Verify signature
            await delete_did_message.verify_signed_field(
                field_name="body",
                wallet=wallet,
                signer_verkey=DIDMyData.from_did(
                    delete_did_message.body.did).public_key_b58
            )
        except BaseModelError as e:
            # Send problem-report message.

            mydata_did_problem_report = MyDataDIDProblemReportMessage(
                problem_code=MyDataDIDProblemReportMessageReason.MESSAGE_BODY_SIGNATURE_VERIFICATION_FAILED,
                explain="Invalid signature.",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=str(int(datetime.datetime.utcnow().timestamp()))
            )

            # Assign thread id
            mydata_did_problem_report.assign_thread_id(
                thid=delete_did_message._id)

            if responder:
                await responder.send_reply(mydata_did_problem_report, connection_id=self.context.connection_record.connection_id)

            return

        # Update MyData DID Registry DID info record with revoked status
        mydata_did_registry_did_info_record.tags["status"] = "revoked"
        await storage.update_record_tags(
            record=mydata_did_registry_did_info_record,
            tags=mydata_did_registry_did_info_record.tags,
        )

        # Send delete-did-response message
        delete_did_response_message = DeleteDIDResponseMessage(
            from_did=response_message_from_did.did,
            to_did=response_message_to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
            body=DeleteDIDResponseMessageBody(
                did=mydata_did_registry_did_info_record.tags.get("did"),
                status=mydata_did_registry_did_info_record.tags.get("status"),
            )
        )

        # Assign thread id
        delete_did_response_message.assign_thread_id(
            thid=delete_did_message._id)

        # Create transaction record to keep track of didcomm messages
        transaction_record = MyDataDIDRegistryDIDCommTransactionRecord(
            thread_id=delete_did_message._id,
            message_type=MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_DELETE_DID,
            messages_list=[delete_did_message.to_json(
            ), delete_did_response_message.to_json()],
            connection_id=self.context.connection_record.connection_id,
        )

        # Save transaction record
        await transaction_record.save(self.context)

        if responder:
            await responder.send_reply(delete_did_response_message, connection_id=self.context.connection_record.connection_id)

    async def process_delete_did_response_message(self, delete_did_response_message: DeleteDIDResponseMessage, receipt: MessageReceipt):
        """
        Process delete-did-response DIDComm message
        """
        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        # Thread identifier
        thread_id = delete_did_response_message._thread_id

        mydata_did_registry_didcomm_transaction_record = None
        try:

            # Fetch MyData DID registry didcomm transaction record
            mydata_did_registry_didcomm_transaction_record: MyDataDIDRegistryDIDCommTransactionRecord = await MyDataDIDRegistryDIDCommTransactionRecord.retrieve_by_tag_filter(
                context=self.context,
                tag_filter={"thread_id": thread_id}
            )

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # No record found
            self._logger.debug(
                "Failed to process delete-did-response message; "
                "No MyData DID registry didcomm transaction record found for thread_id: %s", thread_id
            )
            return

        # Assert transaction record is not None
        assert mydata_did_registry_didcomm_transaction_record is not None

        mydata_did_registry_didcomm_transaction_record.messages_list.append(
            delete_did_response_message.to_json()
        )

        # Update transaction record
        await mydata_did_registry_didcomm_transaction_record.save(self.context)

        try:
            # Mark remote did status as revoked
            mydata_did_remote_record = await storage.search_records(
                type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REMOTE,
                tag_query={"did": delete_did_response_message.body.did}
            ).fetch_single()

            mydata_did_remote_record.tags["status"] = "revoked"

            await storage.update_record_tags(
                record=mydata_did_remote_record,
                tags=mydata_did_remote_record.tags,
            )

        except (StorageNotFoundError, StorageDuplicateError) as e:
            # No record found
            self._logger.debug(
                "Failed to process delete-did-response message; "
                "No MyData DID remote record found for did: %s", delete_did_response_message.body.did
            )
            return

    async def send_delete_did_message(self, did: str) -> MyDataDIDRegistryDIDCommTransactionRecord:
        """
        Send delete-did DIDComm message
        """

        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        connection_record, err = await self.fetch_mydata_did_registry_connection_record()
        if err:
            raise ADAManagerError(
                f"Failed to send read-did message. "
                f"Reason: {err}"
            )

        # from_did
        pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
        from_did = DIDMyData.from_public_key_b58(
            pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

        # to_did
        pairwise_remote_did_record = await storage.search_records(
            type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
            tag_query={"did": connection_record.their_did}
        ).fetch_single()
        to_did = DIDMyData.from_public_key_b58(
            pairwise_remote_did_record.value, key_type=KeyType.ED25519)

        # To be deleted did

        # Fetch did:sov local did record for to deleted mydata did
        to_be_deleted_sov_did = await wallet.get_local_did_for_verkey(
            verkey=DIDMyData.from_did(did).public_key_b58
        )

        # Create delete-did message
        delete_did_message = DeleteDIDMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
            body=DeleteDIDMessageBody(
                did=did
            )
        )

        # Sign message
        await delete_did_message.sign_field(
            field_name="body",
            signer_verkey=to_be_deleted_sov_did.verkey,
            wallet=wallet,
            timestamp=time.time()
        )

        # Create transaction record
        transaction_record = MyDataDIDRegistryDIDCommTransactionRecord(
            thread_id=delete_did_message._id,
            message_type=MyDataDIDRegistryDIDCommTransactionRecord.MESSAGE_TYPE_DELETE_DID,
            messages_list=[delete_did_message.to_json()],
            connection_id=connection_record.connection_id,
        )

        # Save transaction record
        await transaction_record.save(self.context, reason="Send delete-did message")

        # Send delete-did message to MyData DID Registry
        responder: BaseResponder = await self.context.inject(BaseResponder, required=False)
        if responder:
            await responder.send(delete_did_message, connection_id=connection_record.connection_id)

        return transaction_record

    async def send_read_data_agreement_message(self, connection_record: ConnectionRecord, data_agreement_id: str) -> DataAgreementCRUDDIDCommTransaction:
        """
        Send a read-data-agreement message to the remote agent.
        """

        # Fetch context objects
        # Fetch the wallet instance from the context
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        # Fetch the storage instance from the context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        try:
            # from_did
            pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
            from_did = DIDMyData.from_public_key_b58(
                pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

            # to_did
            pairwise_remote_did_record = await storage.search_records(
                type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
                tag_query={"did": connection_record.their_did}
            ).fetch_single()
            to_did = DIDMyData.from_public_key_b58(
                pairwise_remote_did_record.value, key_type=KeyType.ED25519)
        except StorageError as err:
            raise ADAManagerError(
                f"Failed to send read-data-agreement message: {err}"
            )

        # Create the read-data-agreement message
        data_agreement_message = ReadDataAgreement(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
            body=ReadDataAgreementBody(
                data_agreement_id=data_agreement_id,
            )
        )

        # Create transaction record to keep track of read-data-agreement message lifecycle
        transaction_record = DataAgreementCRUDDIDCommTransaction(
            thread_id=data_agreement_message._id,
            message_type=DataAgreementCRUDDIDCommTransaction.MESSAGE_TYPE_READ_DATA_AGREEMENT,
            messages_list=[data_agreement_message.serialize()],
            connection_id=connection_record.connection_id,
        )
        # Add the transaction record to the storage
        await transaction_record.save(self.context)

        responder: BaseResponder = await self.context.inject(BaseResponder, required=False)

        if responder:
            await responder.send(data_agreement_message, connection_id=connection_record.connection_id)

        return transaction_record

    async def process_data_agreement_problem_report_message(self, *, data_agreement_problem_report_message: DataAgreementProblemReport, receipt: MessageReceipt):
        """Process data agreement problem report message"""

        thread_id = data_agreement_problem_report_message._thread_id

        # Fetch data agreement didcomm crud transaction record
        transaction_records = await DataAgreementCRUDDIDCommTransaction.query(
            context=self.context,
            tag_filter={"thread_id": thread_id},
        )

        if len(transaction_records) == 1:
            transaction_record: DataAgreementCRUDDIDCommTransaction = transaction_records[0]

            # Update transaction record with problem report
            transaction_record.messages_list.append(
                data_agreement_problem_report_message.serialize()
            )

            await transaction_record.save(self.context)

    async def process_read_data_agreement_message(self, *, read_data_agreement_message: ReadDataAgreement, receipt: MessageReceipt):

        storage: IndyStorage = await self.context.inject(BaseStorage)
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        # fetch the data agreement record from the wallet
        # create data agreement didcomm crud transaction record
        # save request and response messages
        # send the response message.

        # Create data agreement didcomm crud transaction record
        data_agreement_crud_didcomm_transaction_record = DataAgreementCRUDDIDCommTransaction(
            thread_id=read_data_agreement_message._thread_id,
            message_type=DataAgreementCRUDDIDCommTransaction.MESSAGE_TYPE_READ_DATA_AGREEMENT,
            messages_list=[read_data_agreement_message.serialize()],
            connection_id=self.context.connection_record.connection_id,
        )

        await data_agreement_crud_didcomm_transaction_record.save(self.context)

        try:

            # Fetch the data agreement instance metadata
            data_agreement_instance_metadata_records = await self.query_data_agreement_instance_metadata(
                tag_query={
                    'data_agreement_id': read_data_agreement_message.body.data_agreement_id,
                }
            )

            # Check if there is a data agreement instance metadata record
            if not data_agreement_instance_metadata_records:
                self._logger.info(
                    "Data agreement not found; Failed to process read-data-agreement message data agreement: %s",
                    read_data_agreement_message.body.data_agreement_id,
                )

                # send problem report
                problem_report = DataAgreementProblemReport(
                    from_did=read_data_agreement_message.to_did,
                    to_did=read_data_agreement_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    problem_code=DataAgreementProblemReportReason.DATA_AGREEMENT_NOT_FOUND.value,
                    explain=f"Data agreement not found; Failed to process read-data-agreement message data agreement: {read_data_agreement_message.body.data_agreement_id}",
                )

                problem_report.assign_thread_id(
                    thid=read_data_agreement_message._thread_id
                )

                # Update data agreement crud diddcomm transaction record with response message
                data_agreement_crud_didcomm_transaction_record.messages_list.append(
                    problem_report.serialize()
                )
                await data_agreement_crud_didcomm_transaction_record.save(self.context)

                if responder:
                    await responder.send_reply(problem_report, connection_id=receipt.connection_id)

                return None

            if len(data_agreement_instance_metadata_records) > 1:
                self._logger.info(
                    "Duplicate data agreement records found; Failed to process read-data-agreement message data agreement: %s",
                    read_data_agreement_message.body.data_agreement_id,
                )

                # send problem report
                problem_report = DataAgreementProblemReport(
                    from_did=read_data_agreement_message.to_did,
                    to_did=read_data_agreement_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    problem_code=DataAgreementProblemReportReason.READ_DATA_AGREEMENT_FAILED.value,
                    explain=f"Duplicate data agreement records found; Failed to process read-data-agreement message data agreement: {read_data_agreement_message.body.data_agreement_id}",
                )

                problem_report.assign_thread_id(
                    thid=read_data_agreement_message._thread_id
                )

                # Update data agreement crud diddcomm transaction record with response message
                data_agreement_crud_didcomm_transaction_record.messages_list.append(
                    problem_report.serialize()
                )
                await data_agreement_crud_didcomm_transaction_record.save(self.context)

                if responder:
                    await responder.send_reply(problem_report, connection_id=receipt.connection_id)

                return None

            data_agreement_instance_metadata_record: StorageRecord = data_agreement_instance_metadata_records[
                0]

            # Identify the method of use

            if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:

                # If method of use is data-source

                # Fetch exchante record (credential exchange if method of use is "data-source")
                tag_filter = {}
                post_filter = {
                    "data_agreement_id": read_data_agreement_message.body.data_agreement_id
                }
                records = await V10CredentialExchange.query(self.context, tag_filter, post_filter)

                if not records:
                    self._logger.info(
                        "Credential exchange record not found; Failed to process read-data-agreement message data agreement: %s",
                        read_data_agreement_message.body.data_agreement_id,
                    )

                    # send problem report
                    problem_report = DataAgreementProblemReport(
                        from_did=read_data_agreement_message.to_did,
                        to_did=read_data_agreement_message.from_did,
                        created_time=str(
                            int(datetime.datetime.utcnow().timestamp())),
                        problem_code=DataAgreementProblemReportReason.READ_DATA_AGREEMENT_FAILED.value,
                        explain=f"Credential exchange record not found; Failed to process read-data-agreement message data agreement: {read_data_agreement_message.body.data_agreement_id}",
                    )

                    problem_report.assign_thread_id(
                        thid=read_data_agreement_message._thread_id
                    )

                    # Update data agreement crud diddcomm transaction record with response message
                    data_agreement_crud_didcomm_transaction_record.messages_list.append(
                        problem_report.serialize()
                    )
                    await data_agreement_crud_didcomm_transaction_record.save(self.context)

                    if responder:
                        await responder.send_reply(problem_report, connection_id=receipt.connection_id)

                    return None

                if len(records) > 1:
                    self._logger.info(
                        "Duplicate credential exchange records found; Failed to process read-data-agreement message data agreement: %s",
                        read_data_agreement_message.body.data_agreement_id,
                    )

                    # send problem report
                    problem_report = DataAgreementProblemReport(
                        from_did=read_data_agreement_message.to_did,
                        to_did=read_data_agreement_message.from_did,
                        created_time=str(
                            int(datetime.datetime.utcnow().timestamp())),
                        problem_code=DataAgreementProblemReportReason.READ_DATA_AGREEMENT_FAILED.value,
                        explain=f"Duplicate credential exchange records found; Failed to process read-data-agreement message data agreement: {read_data_agreement_message.body.data_agreement_id}",
                    )

                    problem_report.assign_thread_id(
                        thid=read_data_agreement_message._thread_id
                    )

                    # Update data agreement crud diddcomm transaction record with response message
                    data_agreement_crud_didcomm_transaction_record.messages_list.append(
                        problem_report.serialize()
                    )
                    await data_agreement_crud_didcomm_transaction_record.save(self.context)

                    if responder:
                        await responder.send_reply(problem_report, connection_id=receipt.connection_id)

                    return None

                cred_ex_record: V10CredentialExchange = records[0]

                # Construct data agreement instance

                data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema(
                ).load(cred_ex_record.data_agreement)

                # Construct response message
                read_data_agreement_response_message = ReadDataAgreementResponse(
                    from_did=read_data_agreement_message.to_did,
                    to_did=read_data_agreement_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    body=ReadDataAgreementResponseBody(
                        data_agreement=data_agreement_instance
                    )
                )

                read_data_agreement_response_message.assign_thread_id(
                    thid=read_data_agreement_message._thread_id
                )

                # Update data agreement crud diddcomm transaction record with response message
                data_agreement_crud_didcomm_transaction_record.messages_list.append(
                    read_data_agreement_response_message.serialize()
                )
                await data_agreement_crud_didcomm_transaction_record.save(self.context)

                if responder:
                    await responder.send_reply(read_data_agreement_response_message, connection_id=receipt.connection_id)

                return None

            if data_agreement_instance_metadata_record.tags.get("method_of_use") == DataAgreementV1Record.METHOD_OF_USE_DATA_USING_SERVICE:

                # If method of use is data-using-service

                # Fetch exchange record (presentation exchange if method of use is "data-using-service")
                tag_filter = {}
                post_filter = {
                    "data_agreement_id": read_data_agreement_message.body.data_agreement_id
                }
                records = await V10PresentationExchange.query(self.context, tag_filter, post_filter)

                if not records:
                    self._logger.info(
                        "Presentation exchange record not found; Failed to process read-data-agreement message data agreement: %s",
                        read_data_agreement_message.body.data_agreement_id,
                    )

                    # send problem report
                    problem_report = DataAgreementProblemReport(
                        from_did=read_data_agreement_message.to_did,
                        to_did=read_data_agreement_message.from_did,
                        created_time=str(
                            int(datetime.datetime.utcnow().timestamp())),
                        problem_code=DataAgreementProblemReportReason.READ_DATA_AGREEMENT_FAILED.value,
                        explain=f"Presentation exchange record not found; Failed to process read-data-agreement message data agreement: {read_data_agreement_message.body.data_agreement_id}",
                    )

                    problem_report.assign_thread_id(
                        thid=read_data_agreement_message._thread_id
                    )

                    # Update data agreement crud diddcomm transaction record with response message
                    data_agreement_crud_didcomm_transaction_record.messages_list.append(
                        problem_report.serialize()
                    )
                    await data_agreement_crud_didcomm_transaction_record.save(self.context)

                    if responder:
                        await responder.send_reply(problem_report, connection_id=receipt.connection_id)

                    return None

                if len(records) > 1:
                    self._logger.info(
                        "Duplicate presentation exchange records found; Failed to process read-data-agreement message data agreement: %s",
                        read_data_agreement_message.body.data_agreement_id,
                    )

                    # send problem report
                    problem_report = DataAgreementProblemReport(
                        from_did=read_data_agreement_message.to_did,
                        to_did=read_data_agreement_message.from_did,
                        created_time=str(
                            int(datetime.datetime.utcnow().timestamp())),
                        problem_code=DataAgreementProblemReportReason.READ_DATA_AGREEMENT_FAILED.value,
                        explain=f"Duplicate presentation exchange records found; Failed to process read-data-agreement message data agreement: {read_data_agreement_message.body.data_agreement_id}",
                    )

                    problem_report.assign_thread_id(
                        thid=read_data_agreement_message._thread_id
                    )

                    # Update data agreement crud diddcomm transaction record with response message
                    data_agreement_crud_didcomm_transaction_record.messages_list.append(
                        problem_report.serialize()
                    )
                    await data_agreement_crud_didcomm_transaction_record.save(self.context)

                    if responder:
                        await responder.send_reply(problem_report, connection_id=receipt.connection_id)

                    return None

                pres_ex_record: V10PresentationExchange = records[0]

                # Construct data agreement instance

                data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema(
                ).load(pres_ex_record.data_agreement)

                # Construct response message
                read_data_agreement_response_message = ReadDataAgreementResponse(
                    from_did=read_data_agreement_message.to_did,
                    to_did=read_data_agreement_message.from_did,
                    created_time=str(
                        int(datetime.datetime.utcnow().timestamp())),
                    body=ReadDataAgreementResponseBody(
                        data_agreement=data_agreement_instance
                    )
                )

                read_data_agreement_response_message.assign_thread_id(
                    thid=read_data_agreement_message._thread_id
                )

                # Update data agreement crud diddcomm transaction record with response message
                data_agreement_crud_didcomm_transaction_record.messages_list.append(
                    read_data_agreement_response_message.serialize()
                )
                await data_agreement_crud_didcomm_transaction_record.save(self.context)

                if responder:
                    await responder.send_reply(read_data_agreement_response_message, connection_id=receipt.connection_id)

                return None

        except (ADAManagerError, StorageError) as e:
            # send problem report
            problem_report = DataAgreementProblemReport(
                from_did=read_data_agreement_message.to_did,
                to_did=read_data_agreement_message.from_did,
                created_time=str(
                    int(datetime.datetime.utcnow().timestamp())),
                problem_code=DataAgreementProblemReportReason.READ_DATA_AGREEMENT_FAILED.value,
                explain=str(e)
            )

            problem_report.assign_thread_id(
                thid=read_data_agreement_message._thread_id
            )

            # Update data agreement crud diddcomm transaction record with response message
            data_agreement_crud_didcomm_transaction_record.messages_list.append(
                problem_report.serialize()
            )
            await data_agreement_crud_didcomm_transaction_record.save(self.context)

            if responder:
                await responder.send_reply(problem_report, connection_id=receipt.connection_id)

    async def fetch_data_agreement_crud_didcomm_transactions_from_wallet(self):
        try:
            return await DataAgreementCRUDDIDCommTransaction.query(
                self.context,
            )
        except StorageSearchError as e:
            raise ADAManagerError(
                f"Failed to fetch data agreement CRUD DIDComm transactions from wallet: {e}"
            )

    async def process_read_data_agreement_response_message(self, read_data_agreement_response_message: ReadDataAgreementResponse, receipt: MessageReceipt):
        try:
            # Fetch Data Agreement crud txn from wallet using the thread_id of the message
            da_crud_didcomm_txn = await DataAgreementCRUDDIDCommTransaction.retrieve_by_tag_filter(
                self.context,
                {"thread_id": read_data_agreement_response_message._thread_id}
            )
            # Update the txn record with response message
            da_crud_didcomm_txn.messages_list.append(
                read_data_agreement_response_message.to_json())
            await da_crud_didcomm_txn.save(self.context)

        except (StorageNotFoundError, StorageDuplicateError):
            pass

    async def create_and_store_data_agreement_in_wallet(self, data_agreement: dict) -> DataAgreementV1Record:
        """
        Create and store a data agreement in the wallet.
        """

        personal_data_list = data_agreement.get("personal_data", [])

        personal_data_new_list = []
        personal_data_new_list_for_proof_request = []

        try:

            for personal_data in personal_data_list:

                # Check if the personal data is already in the wallet
                personal_data_record: DataAgreementPersonalDataRecord = await DataAgreementPersonalDataRecord.retrieve_by_id(self.context, personal_data.get("attribute_id"))

                if personal_data_record:

                    personal_data_new_list.append({
                        "attribute_id": personal_data_record.data_agreement_personal_data_record_id,
                        "attribute_name": personal_data_record.attribute_name,
                        "attribute_category": personal_data_record.attribute_category,
                        "attribute_sensitive": personal_data_record.attribute_sensitive,
                        "attribute_description": personal_data_record.attribute_description,
                    })

                    personal_data_new_list_for_proof_request.append({
                        "attribute_name": personal_data_record.attribute_name,
                        "restrictions": personal_data.get("restrictions", [])
                    })

        except (StorageNotFoundError, StorageError) as e:
            raise ADAManagerError(
                f"Failed to create data agreement: {e}"
            )

        # Replace the personal data list with the new list
        data_agreement["personal_data"] = personal_data_new_list

        # Generate data agreement model class instance
        data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(data_agreement)

        # Set data agreement version
        data_agreement.data_agreement_template_version = 1

        # Set data agreement identifier
        data_agreement.data_agreement_template_id = str(uuid.uuid4())

        # Create the data agreement record
        data_agreement_v1_record = DataAgreementV1Record(
            data_agreement_id=data_agreement.data_agreement_template_id,
            method_of_use=data_agreement.method_of_use,
            state=DataAgreementV1Record.STATE_PREPARATION,
            data_agreement=data_agreement.serialize(),
            published_flag="True"
        )

        if data_agreement.method_of_use == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:
            # If method-of-use is "data-source", then create a schema and credential defintion

            ledger: BaseLedger = await self.context.inject(BaseLedger, required=False)
            if not ledger:
                reason = "No ledger available"
                if not self.context.settings.get_value("wallet.type"):
                    reason += ": missing wallet-type?"

                self._logger.error(
                    f"Failed to create data agreement: {reason}")

                return None

            issuer: BaseIssuer = await self.context.inject(BaseIssuer)

            async with ledger:
                try:

                    # Create schema

                    schema_name = data_agreement.usage_purpose
                    schema_version = str(semver.VersionInfo(
                        str(data_agreement.data_agreement_template_version)))
                    attributes = [
                        personal_data.attribute_name
                        for personal_data in data_agreement.personal_data
                    ]

                    schema_id, schema_def = await shield(
                        ledger.create_and_send_schema(
                            issuer, schema_name, schema_version, attributes
                        )
                    )

                    # Create credential definition

                    tag = "default"
                    support_revocation = False

                    (cred_def_id, cred_def, novel) = await shield(
                        ledger.create_and_send_credential_definition(
                            issuer,
                            schema_id,
                            signature_type=None,
                            tag=tag,
                            support_revocation=support_revocation,
                        )
                    )

                    # Update the data agreement record with schema and credential definition
                    data_agreement_v1_record.schema_id = schema_id
                    data_agreement_v1_record.cred_def_id = cred_def_id

                except (IssuerError, LedgerError) as err:
                    self._logger.error(
                        f"Failed to create data agreement: {err.roll_up}")
                    return None
        else:
            # If method-of-use is "data-using-service"

            # Update data agreement with proof presentation request
            proof_request_dict = await self.construct_proof_presentation_request_dict_from_data_agreement_personal_data(
                personal_data=personal_data_new_list_for_proof_request,
                usage_purpose=data_agreement.usage_purpose,
                usage_purpose_description=data_agreement.usage_purpose_description,
                data_agreement_template_version=str(semver.VersionInfo(
                    str(data_agreement.data_agreement_template_version)))

            )

            data_agreement_v1_record.data_agreement_proof_presentation_request = proof_request_dict

        # Save the data agreement record
        await data_agreement_v1_record.save(self.context)

        return data_agreement_v1_record

    async def query_data_agreements_in_wallet(self, tag_filter: dict = None) -> typing.List[DataAgreementV1Record]:
        """
        Query data agreements in the wallet.
        """

        try:
            # Add the published_flag tag to the filter
            tag_filter["published_flag"] = "True"

            # If template_version is provided, then data agreements with that version will be returned
            # published_flag flag is not required for this query
            template_version = None
            if "template_version" in tag_filter:
                template_version = tag_filter["template_version"]

                tag_filter.pop("template_version", None)
                tag_filter.pop("published_flag", None)
                tag_filter.pop("delete_flag", None)

            self._logger.info(
                f"Query data agreements in wallet with tag_filter: {tag_filter}")

            # Query data agreements from the wallet
            data_agreement_v1_records: typing.List[DataAgreementV1Record] = await DataAgreementV1Record.query(
                self.context,
                tag_filter=tag_filter
            )

            # Filter data agreements by template_version
            if template_version:
                data_agreement_v1_records = [
                    data_agreement_v1_record for data_agreement_v1_record in data_agreement_v1_records
                    if data_agreement_v1_record.data_agreement.get("template_version") == int(template_version)
                ]

            return data_agreement_v1_records
        except StorageSearchError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch all data agreements from wallet: {e}"
            )

    async def update_data_agreement_in_wallet(self, data_agreement_id: str, data_agreement: dict) -> DataAgreementV1Record:
        """
        Update data agreement in the wallet.
        """

        personal_data_list = data_agreement.get("personal_data", [])

        personal_data_new_list = []
        personal_data_new_list_for_proof_request = []

        try:

            for personal_data in personal_data_list:

                # Check if the personal data is already in the wallet
                personal_data_record: DataAgreementPersonalDataRecord = await DataAgreementPersonalDataRecord.retrieve_by_id(self.context, personal_data.get("attribute_id"))

                if personal_data_record:

                    personal_data_new_list.append({
                        "attribute_id": personal_data_record.data_agreement_personal_data_record_id,
                        "attribute_name": personal_data_record.attribute_name,
                        "attribute_category": personal_data_record.attribute_category,
                        "attribute_sensitive": personal_data_record.attribute_sensitive,
                        "attribute_description": personal_data_record.attribute_description,
                    })

                    personal_data_new_list_for_proof_request.append({
                        "attribute_name": personal_data_record.attribute_name,
                        "restrictions": personal_data.get("restrictions", [])
                    })

            # Replace the personal data list with the new list
            data_agreement["personal_data"] = personal_data_new_list

            # Generate data agreement model class instance
            data_agreement: DataAgreementV1 = DataAgreementV1Schema().load(data_agreement)

            # Tag filter
            tag_filter = {
                "data_agreement_id": data_agreement_id,
                "published_flag": "True",
                "delete_flag": "False",
            }

            # Query for the old data agreement record by id
            old_data_agreement_record: DataAgreementV1Record = await DataAgreementV1Record.retrieve_by_tag_filter(
                self.context,
                tag_filter=tag_filter
            )

            # Update the published_flag status for the old data agreement record
            old_data_agreement_record.published_flag = "False"

            # Update the old data agreement record
            await old_data_agreement_record.save(self.context)

            # Set the data agreement version for the new data agreement (increment by 1)
            data_agreement.data_agreement_template_version = old_data_agreement_record.data_agreement.get(
                "template_version") + 1
            data_agreement.data_agreement_template_id = data_agreement_id

            # Create the new data agreement record
            new_data_agreement_record = DataAgreementV1Record(
                data_agreement_id=data_agreement_id,
                method_of_use=data_agreement.method_of_use,
                state=DataAgreementV1Record.STATE_PREPARATION,
                data_agreement=data_agreement.serialize(),
                published_flag="True"
            )

            if data_agreement.method_of_use == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:
                # If method-of-use is "data-source", then create a schema and credential defintion

                ledger: BaseLedger = await self.context.inject(BaseLedger, required=False)
                if not ledger:
                    reason = "No ledger available"
                    if not self.context.settings.get_value("wallet.type"):
                        reason += ": missing wallet-type?"

                    self._logger.error(
                        f"Failed to create data agreement: {reason}")

                    return None

                issuer: BaseIssuer = await self.context.inject(BaseIssuer)

                async with ledger:
                    try:

                        # Create schema

                        schema_name = data_agreement.usage_purpose
                        schema_version = str(semver.VersionInfo(
                            str(data_agreement.data_agreement_template_version)))
                        attributes = [
                            personal_data["attribute_name"]
                            for personal_data in data_agreement["personal_data"]
                        ]

                        schema_id, schema_def = await shield(
                            ledger.create_and_send_schema(
                                issuer, schema_name, schema_version, attributes
                            )
                        )

                        # Create credential definition

                        tag = "default"
                        support_revocation = False

                        (cred_def_id, cred_def, novel) = await shield(
                            ledger.create_and_send_credential_definition(
                                issuer,
                                schema_id,
                                signature_type=None,
                                tag=tag,
                                support_revocation=support_revocation,
                            )
                        )

                        # Update the data agreement record with schema and credential definition
                        new_data_agreement_record.schema_id = schema_id
                        new_data_agreement_record.cred_def_id = cred_def_id

                    except (IssuerError, LedgerError) as err:
                        self._logger.error(
                            f"Failed to create data agreement: {err.roll_up}")
                        return None
            else:
                # If method-of-use is "data-using-service"

                # Update data agreement with proof presentation request
                proof_request_dict = await self.construct_proof_presentation_request_dict_from_data_agreement_personal_data(
                    personal_data=personal_data_new_list_for_proof_request,
                    usage_purpose=data_agreement.usage_purpose,
                    usage_purpose_description=data_agreement.usage_purpose_description,
                    data_agreement_template_version=str(semver.VersionInfo(
                        str(data_agreement.data_agreement_template_version)))
                )

                new_data_agreement_record.data_agreement_proof_presentation_request = proof_request_dict

            # Save the new data agreement record
            await new_data_agreement_record.save(self.context)

            return new_data_agreement_record

        except StorageSearchError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to update data agreement; An error occured while fetching DA : {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to update data agreement; Multiple DA records were found in the wallet: {e}"
            )
        except StorageNotFoundError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to update data agreement; No DA record was found in the wallet: {e}"
            )
        except StorageError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to update data agreement: {e}"
            )

    async def delete_data_agreement_in_wallet(self, data_agreement_id: str):
        """
        Delete data agreement in wallet
        """

        try:
            # Tag filter

            tag_filter = {
                "data_agreement_id": data_agreement_id,
                "published_flag": "True",
                "delete_flag": "False",
            }

            # Query for the old data agreement record by id
            old_data_agreement_record: DataAgreementV1Record = await DataAgreementV1Record.retrieve_by_tag_filter(
                self.context,
                tag_filter=tag_filter
            )

            # Update the delete_flag status for the old data agreement record
            old_data_agreement_record.delete_flag = "True"

            if old_data_agreement_record.method_of_use == DataAgreementV1Record.METHOD_OF_USE_DATA_SOURCE:

                # Delete credential definition if method-of-use is "data-source"

                storage = await self.context.inject(BaseStorage)
                cred_def_records = await storage.search_records(
                    type_filter=CRED_DEF_SENT_RECORD_TYPE,
                    tag_query={
                        "cred_def_id": old_data_agreement_record.cred_def_id
                    },
                ).fetch_all()

                if cred_def_records:
                    for cred_def_record in cred_def_records:
                        await storage.delete_record(cred_def_record)
            else:
                # nothing to perform
                pass

            # Update the old data agreement record
            await old_data_agreement_record.save(self.context)
        except StorageSearchError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to delete data agreement; An error occured while fetching DA : {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to delete data agreement; Multiple DA records were found in the wallet: {e}"
            )
        except StorageNotFoundError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to delete data agreement; No DA record was found in the wallet: {e}"
            )

    async def query_data_agreement_version_history(self, data_agreement_id: str) -> typing.List[DataAgreementV1Record]:
        """
        Query data agreements in the wallet.
        """

        try:
            # Tag filter
            tag_filter = {
                "data_agreement_id": data_agreement_id,
            }

            # Query for the old data agreement record by id
            data_agreement_v1_records: typing.List[DataAgreementV1Record] = await DataAgreementV1Record.query(
                self.context,
                tag_filter=tag_filter
            )

            return data_agreement_v1_records
        except StorageSearchError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch all data agreements from wallet: {e}"
            )

    async def create_and_store_da_personal_data_in_wallet(self, personal_data: DataAgreementPersonalData) -> DataAgreementPersonalDataRecord:
        """
        Create and store personal data in the wallet.
        """
        new_personal_data_record = DataAgreementPersonalDataRecord(
            attribute_name=personal_data.attribute_name,
            attribute_category=personal_data.attribute_category,
            attribute_sensitive="True" if personal_data.attribute_sensitive else "False",
            attribute_description=personal_data.attribute_description,
        )

        await new_personal_data_record.save(self.context)

        return new_personal_data_record

    async def query_da_personal_data_in_wallet(self, tag_filter: dict = None) -> typing.List[DataAgreementPersonalDataRecord]:
        """
        Query personal data in the wallet.
        """

        try:

            # Query for the old data agreement record by id
            personal_data_records: typing.List[DataAgreementPersonalDataRecord] = await DataAgreementPersonalDataRecord.query(
                self.context,
                tag_filter=tag_filter
            )

            return personal_data_records
        except StorageSearchError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch all data agreements from wallet: {e}"
            )

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

    async def mark_connection_id_as_auditor(self, connection_record: ConnectionRecord):
        """Associate the connection with Auditor"""

        assert connection_record.connection_id, "Connection ID is required"

        try:

            # Fetch storage from context
            storage: IndyStorage = await self.context.inject(BaseStorage)

            # Search for existing connection_id marked as Auditor
            connection_record_list = await storage.search_records(
                self.RECORD_TYPE_AUDITOR_CONNECTION,
                {"connection_id": connection_record.connection_id},
            ).fetch_all()

            # If no record found, create a new one
            if not connection_record_list:
                record = StorageRecord(
                    self.RECORD_TYPE_AUDITOR_CONNECTION,
                    connection_record.connection_id,
                    {"connection_id": connection_record.connection_id},
                )

                await storage.add_record(record)
            else:
                # Update the existing record with the new connection_id
                record = connection_record_list[0]

                await storage.update_record_value(record=record, value=connection_record.connection_id)
                await storage.update_record_tags(record=record, tags={"connection_id": connection_record.connection_id})

        except StorageError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to mark connection as Auditor: {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to mark connection as Auditor: {e}"
            )

    async def fetch_current_auditor_connection_id(self) -> typing.Union[None, str]:
        """
        Fetch current Auditor connection id.
        """

        try:

            # Fetch storage from context
            storage: IndyStorage = await self.context.inject(BaseStorage)

            # Search for existing connection_id marked as Auditor
            connection_record_list = await storage.search_records(
                self.RECORD_TYPE_AUDITOR_CONNECTION,
            ).fetch_all()

            if len(connection_record_list) > 1:
                # Raise an error
                raise ADAManagerError(
                    f"More than one connection marked as Auditor"
                )

            if not connection_record_list:
                # if no record found
                return None
            else:
                # if record found
                record = connection_record_list[0]

                return record.value
        except StorageError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch current Auditor connection id: {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch current Auditor connection id: {e}"
            )

    async def unmark_connection_id_as_auditor(self) -> bool:
        """
        Disassociate the connection with Auditor.
        """

        try:

            # Fetch storage from context
            storage: IndyStorage = await self.context.inject(BaseStorage)

            # Search for existing connection_id marked as Auditor
            connection_record_list = await storage.search_records(
                self.RECORD_TYPE_AUDITOR_CONNECTION,
            ).fetch_all()

            if not connection_record_list:
                # if no record found
                return False
            else:
                # if record found
                record = connection_record_list[0]

                await storage.delete_record(record)

                return True

        except StorageError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to unmark connection as Auditor: {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to unmark connection as Auditor: {e}"
            )

    async def mark_connection_id_as_mydata_did_registry(self, connection_record: ConnectionRecord):
        """
        Associate the connection with MyData DID registry.
        """

        assert connection_record.connection_id, "Connection ID is required"

        try:

            # Fetch storage from context
            storage: IndyStorage = await self.context.inject(BaseStorage)

            # Search for existing connection_id marked as MyData DID registry
            connection_record_list = await storage.search_records(
                self.RECORD_TYPE_MYDATA_DID_REGISTRY_CONNECTION,
                {"connection_id": connection_record.connection_id},
            ).fetch_all()

            # If no record found, create a new one
            if not connection_record_list:
                record = StorageRecord(
                    self.RECORD_TYPE_MYDATA_DID_REGISTRY_CONNECTION,
                    connection_record.connection_id,
                    {"connection_id": connection_record.connection_id},
                )

                await storage.add_record(record)
            else:
                # Update the existing record with the new connection_id
                record = connection_record_list[0]

                await storage.update_record_value(record=record, value=connection_record.connection_id)
                await storage.update_record_tags(record=record, tags={"connection_id": connection_record.connection_id})

        except StorageError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to mark connection as MyData DID registry: {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to mark connection as MyData DID registry: {e}"
            )

    async def fetch_current_mydata_did_registry_connection_id(self) -> typing.Union[None, str]:
        """
        Fetch current MyData DID registry connection id.
        """

        try:

            # Fetch storage from context
            storage: IndyStorage = await self.context.inject(BaseStorage)

            # Search for existing connection_id marked as MyData DID registry
            connection_record_list = await storage.search_records(
                self.RECORD_TYPE_MYDATA_DID_REGISTRY_CONNECTION,
            ).fetch_all()

            if len(connection_record_list) > 1:
                # Raise an error
                raise ADAManagerError(
                    f"More than one connection marked as MyData DID registry"
                )

            if not connection_record_list:
                # if no record found
                return None
            else:
                # if record found
                record = connection_record_list[0]

                return record.value
        except StorageError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch current MyData DID registry connection id: {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch current MyData DID registry connection id: {e}"
            )

    async def unmark_connection_id_as_mydata_did_registry(self) -> bool:
        """
        Disassociate the connection with MyData DID registry.
        """

        try:

            # Fetch storage from context
            storage: IndyStorage = await self.context.inject(BaseStorage)

            # Search for existing connection_id marked as MyData DID registry
            connection_record_list = await storage.search_records(
                self.RECORD_TYPE_MYDATA_DID_REGISTRY_CONNECTION,
            ).fetch_all()

            if not connection_record_list:
                # if no record found
                return False
            else:
                # if record found
                record = connection_record_list[0]

                await storage.delete_record(record)

                return True

        except StorageError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to unmark connection as MyData DID registry: {e}"
            )
        except StorageDuplicateError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to unmark connection as MyData DID registry: {e}"
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

        # From DID
        remote_records: StorageRecord = await storage.search_records(
            type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REMOTE,
            tag_query={
                "status": "active"
            }
        ).fetch_all()

        if len(remote_records) < 1:
            raise ADAManagerError(
                f"Failed to construct data agreement offer; "
                f"No active remote MyData DID found"
            )
        controller_mydata_did = DIDMyData.from_did(
            remote_records[0].tags.get("did"))

        # Principle DID from connection record
        pairwise_remote_did_record = await storage.search_records(
            type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
            tag_query={"did": connection_record.their_did}
        ).fetch_single()
        principle_did = DIDMyData.from_public_key_b58(
            pairwise_remote_did_record.value, key_type=KeyType.ED25519)

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
            principle_did=principle_did.did,
            data_policy=data_agreement_body.data_policy,
            personal_data=data_agreement_body.personal_data,
            dpia=data_agreement_body.dpia,
            event=[DataAgreementEvent(
                event_id=f"{controller_mydata_did.did}#1",
                time_stamp=current_datetime_in_iso8601(),
                did=controller_mydata_did.did,
                state=DataAgreementEvent.STATE_OFFER
            )]
        )

        data_agreement_negotiation_offer_body_dict = data_agreement_negotiation_offer_body.serialize()

        signature_options = {
            "id": f"{controller_mydata_did.did}#1",
            "type": "Ed25519Signature2018",
            "created": current_datetime_in_iso8601(),
            "verificationMethod": f"{controller_mydata_did.did}",
            "proofPurpose": "contractAgreement",
        }

        # Generate proofs
        document_with_proof: dict = await sign_data_agreement(
            data_agreement_negotiation_offer_body_dict.copy(
            ), signature_options, controller_mydata_did.public_key_b58, wallet
        )

        data_agreement_offer_proof: DataAgreementProof = DataAgreementProofSchema().load(
            document_with_proof.get("proof"))

        # Update data agreement negotiation offer message with proof
        data_agreement_negotiation_offer_body.proof = data_agreement_offer_proof

        # Construct data agreement negotiation offer message
        data_agreement_negotiation_offer_message = DataAgreementNegotiationOfferMessage(
            from_did=controller_mydata_did.did,
            to_did=principle_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
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
        pairwise_remote_did_record = await storage.search_records(
            type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
            tag_query={"did": connection_record.their_did}
        ).fetch_single()
        to_did = DIDMyData.from_public_key_b58(
            pairwise_remote_did_record.value, key_type=KeyType.ED25519)

        # Create read-did message
        read_did_message = ReadDIDMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
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
            pairwise_remote_did_record = await storage.search_records(
                type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
                tag_query={"did": connection_record.their_did}
            ).fetch_single()
            to_did = DIDMyData.from_public_key_b58(
                pairwise_remote_did_record.value, key_type=KeyType.ED25519)
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
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
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
            pairwise_remote_did_record = await storage.search_records(
                type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
                tag_query={"did": connection_record.their_did}
            ).fetch_single()
            to_did = DIDMyData.from_public_key_b58(
                pairwise_remote_did_record.value, key_type=KeyType.ED25519)
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
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
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
            pairwise_remote_did_record = await storage.search_records(
                type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
                tag_query={"did": connection_record.their_did}
            ).fetch_single()
            to_did = DIDMyData.from_public_key_b58(
                pairwise_remote_did_record.value, key_type=KeyType.ED25519)
        except StorageError as err:
            raise ADAManagerError(
                f"Failed to construct data agreement negotiation problem-report message: {err}"
            )

        # Construct data agreement problem report message
        data_agreement_negotiation_problem_report = DataAgreementNegotiationProblemReport(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
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
            pairwise_remote_did_record = await storage.search_records(
                type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
                tag_query={"did": connection_record.their_did}
            ).fetch_single()
            to_did = DIDMyData.from_public_key_b58(
                pairwise_remote_did_record.value, key_type=KeyType.ED25519)
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
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
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
                            "data_agreement": data_agreement_instance.serialize()
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
                            "data_agreement": data_agreement_instance.serialize()
                        })

                except StorageError:
                    pass

        return data_agreement_instances

    async def construct_data_agreement_verify_request(self, *, data_agreement_id: str) -> DataAgreementVerify:
        """Construct data agreement verify request message"""

        # Wallet instance from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Storage instance from context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        # Fetch auditor connection record
        auditor_connection_record, err = await self.fetch_auditor_connection_record()
        if err:
            raise ADAManagerError(
                f"Failed to construct data agreement verify request message: {err}"
            )
        
        # from_did
        pairwise_local_did_record = await wallet.get_local_did(auditor_connection_record.my_did)
        from_did = DIDMyData.from_public_key_b58(
            pairwise_local_did_record.verkey, key_type=KeyType.ED25519)

        # to_did
        pairwise_remote_did_record = await storage.search_records(
            type_filter=ConnectionManager.RECORD_TYPE_DID_KEY,
            tag_query={"did": auditor_connection_record.their_did}
        ).fetch_single()
        to_did = DIDMyData.from_public_key_b58(
            pairwise_remote_did_record.value, key_type=KeyType.ED25519)

        # Fetch data agreement instance
        data_agreement_instances = await self.query_data_agreement_instances(
            {
                "data_agreement_id": data_agreement_id
            }
        )

        if len(data_agreement_instances) != 1:
            raise ADAManagerError(
                f"Failed to construct data agreement verify request message: "
                f"{len(data_agreement_instances)} data agreement instances found for data agreement id: {data_agreement_id}"
            )
        
        data_agreement_instance: DataAgreementInstance = DataAgreementInstanceSchema().load(
            data_agreement_instances[0].get("data_agreement")
        )

        # Construct data agreement verify message

        data_agreement_verify = DataAgreementVerify(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=str(int(datetime.datetime.utcnow().timestamp())),
            body=DataAgreementVerifyBody(
                data_agreement=data_agreement_instance
            )
        )

        return data_agreement_verify