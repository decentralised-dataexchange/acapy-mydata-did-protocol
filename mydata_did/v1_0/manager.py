import datetime
import logging
import json
import time
import uuid
import typing

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.responder import BaseResponder
from aries_cloudagent.core.dispatcher import DispatcherResponder
from aries_cloudagent.transport.inbound.receipt import MessageReceipt
from aries_cloudagent.core.error import BaseError
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.indy import IndyStorage
from aries_cloudagent.storage.error import StorageNotFoundError, StorageSearchError, StorageDuplicateError, StorageError
from aries_cloudagent.wallet.indy import IndyWallet
from aries_cloudagent.wallet.base import BaseWallet, DIDInfo
from aries_cloudagent.wallet.error import WalletError, WalletNotFoundError
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager

from .messages.create_did import CreateDIDMessage
from .messages.read_did import ReadDIDMessage, ReadDIDMessageBody
from .messages.read_did_response import ReadDIDResponseMessage
from .messages.delete_did import DeleteDIDMessage, DeleteDIDMessageBody
from .messages.delete_did_response import DeleteDIDResponseMessage, DeleteDIDResponseMessageBody
from .messages.create_did_response import CreateDIDResponseMessage
from .messages.problem_report import MyDataDIDProblemReportMessage, MyDataDIDProblemReportMessageReason
from .messages.read_data_agreement import ReadDataAgreement
from .messages.read_data_agreement_response import ReadDataAgreementResponse

from .models.data_agreement_model import DataAgreementV1, DataAgreementPersonalData, DataAgreementV1Schema
from .models.read_data_agreement_model import ReadDataAgreementBody
from .models.diddoc_model import MyDataDIDBody, MyDataDIDResponseBody, MyDataDIDDoc, MyDataDIDDocService, MyDataDIDDocVerificationMethod, MyDataDIDDocAuthentication
from .models.mydata_did_records import MyDataDIDRecord
from .models.read_data_agreement_response_model import ReadDataAgreementResponseBody
from .models.exchange_records.mydata_did_registry_didcomm_transaction_record import MyDataDIDRegistryDIDCommTransactionRecord
from .models.exchange_records.data_agreement_didcomm_transaction_record import DataAgreementCRUDDIDCommTransaction
from .models.exchange_records.data_agreement_record import DataAgreementV1Record
from .models.exchange_records.data_agreement_personal_data_record import DataAgreementPersonalDataRecord, DataAgreementPersonalDataRecordSchema

from .utils.diddoc import DIDDoc
from .utils.did.mydata_did import DIDMyData
from .utils.wallet.key_type import KeyType
from .utils.verification_method import PublicKeyType


class ADAManagerError(BaseError):
    """ADA manager error"""


class ADAManager:

    # Record for indicating a connection is labelled as MyData DID registry (client)
    RECORD_TYPE_MYDATA_DID_REGISTRY_CONNECTION = "mydata_did_registry_connection"

    # Record for indicating a MyData DID is registered in the DID registry (client)
    RECORD_TYPE_MYDATA_DID_REMOTE = "mydata_did_remote"

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
                await responder.send_reply(mydata_did_problem_report, connection_id=self.context.connection_record.connection_id)

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
            await responder.send_reply(read_did_response_message, connection_id=self.context.connection_record.connection_id)

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

    async def send_read_data_agreement_message(self, connection: ConnectionRecord, data_agreement_id: str) -> DataAgreementCRUDDIDCommTransaction:
        """
        Send a read-data-agreement message to the remote agent.
        """

        # Fetch context objects
        # Fetch the wallet instance from the context
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        # Fetch the storage instance from the context
        storage: BaseStorage = await self.context.inject(BaseStorage)

        # My DID and Their DID from the connection object
        connection_from_did = connection.my_did
        connection_to_did = connection.their_did

        # Convert My DID to MyData DID equivalent
        # Query My DID from the wallet
        connection_from_did_info = await wallet.get_local_did(connection_from_did)
        # Fetch the verkey from the wallet
        connection_from_did_verkey = connection_from_did_info.verkey
        # Convert the verkey to MyData DID equivalent
        mydata_from_did = DIDMyData.from_public_key_b58(public_key=connection_from_did_verkey,
                                                        key_type=KeyType.ED25519)

        # Convert Their DID to MyData DID equivalent
        # Query Their DID from the wallet
        connection_to_did_record = await storage.search_records(
            ConnectionManager.RECORD_TYPE_DID_KEY,
            {"did": connection_to_did}
        ).fetch_single()
        # Fetch the verkey from the wallet
        connection_to_did_verkey = connection_to_did_record.value
        # Convert the verkey to MyData DID equivalent
        mydata_to_did = DIDMyData.from_public_key_b58(
            public_key=connection_to_did_verkey,
            key_type=KeyType.ED25519
        )

        # Create the read-data-agreement message
        data_agreement_message = ReadDataAgreement(
            from_did=mydata_from_did.did,
            to_did=mydata_to_did.did,
            created_time=str(int(time.time())),
            body=ReadDataAgreementBody(
                data_agreement_id=data_agreement_id,
            )
        )

        # Create transaction record to keep track of read-data-agreement message lifecycle
        transaction_record = DataAgreementCRUDDIDCommTransaction(
            thread_id=data_agreement_message._id,
            message_type=DataAgreementCRUDDIDCommTransaction.MESSAGE_TYPE_READ_DATA_AGREEMENT,
            messages_list=[data_agreement_message.to_json()]
        )
        # Add the transaction record to the storage
        await transaction_record.save(self.context)

        responder: BaseResponder = await self.context.inject(BaseResponder, required=False)

        if responder:
            await responder.send(data_agreement_message, connection_id=connection.connection_id)

        return transaction_record

    async def process_read_data_agreement_message(self, read_data_agreement_message: ReadDataAgreement, receipt: MessageReceipt):

        storage: IndyStorage = await self.context.inject(BaseStorage)
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        # fetch the data agreement record from the wallet
        try:
            data_agreement_record = await storage.search_records(
                ADAManager.DATA_AGREEMENT_RECORD_TYPE, {
                    "data_agreement_id": read_data_agreement_message.body.data_agreement_id}
            ).fetch_single()

            if data_agreement_record:
                # send the data agreement to the requester
                read_data_agreement_response_message = ReadDataAgreementResponse(
                    from_did=read_data_agreement_message.to_did,
                    to_did=read_data_agreement_message.from_did,
                    created_time=read_data_agreement_message.created_time,
                    body=ReadDataAgreementResponseBody(
                        data_agreement=DataAgreementV1.from_json(
                            data_agreement_record.value)
                    )
                )
                read_data_agreement_response_message.assign_thread_id(
                    thid=read_data_agreement_message._id)

                if responder:
                    await responder.send_reply(read_data_agreement_response_message, connection_id=receipt.connection_id)
        except StorageNotFoundError:
            # send problem report
            pass

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

        try:

            for personal_data in personal_data_list:

                # Check if the personal data is already in the wallet
                personal_data_record: DataAgreementPersonalDataRecord = await DataAgreementPersonalDataRecord.retrieve_by_id(self.context, personal_data.get("attribute_id"))

                if personal_data_record:

                    temp_personal_data = {
                        "attribute_id": personal_data_record.data_agreement_personal_data_record_id,
                        "attribute_name": personal_data_record.attribute_name,
                        "attribute_category": personal_data_record.attribute_category,
                        "attribute_sensitive": personal_data_record.attribute_sensitive,
                        "attribute_description": personal_data_record.attribute_description,
                    }

                    personal_data_new_list.append(temp_personal_data)

        except (StorageNotFoundError, StorageError) as e:
            raise ADAManagerError(
                f"Failed to create data agreement: {e}"
            )

        # Replace the personal data list with the new list
        data_agreement["personal_data"] = personal_data_new_list

        # Generate data agreement model class instance
        data_agreement = DataAgreementV1Schema().load(data_agreement)

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

        try:

            for personal_data in personal_data_list:

                # Check if the personal data is already in the wallet
                personal_data_record: DataAgreementPersonalDataRecord = await DataAgreementPersonalDataRecord.retrieve_by_id(self.context, personal_data.get("attribute_id"))

                if personal_data_record:

                    temp_personal_data = {
                        "attribute_id": personal_data_record.data_agreement_personal_data_record_id,
                        "attribute_name": personal_data_record.attribute_name,
                        "attribute_category": personal_data_record.attribute_category,
                        "attribute_sensitive": personal_data_record.attribute_sensitive,
                        "attribute_description": personal_data_record.attribute_description,
                    }

                    personal_data_new_list.append(temp_personal_data)

            # Replace the personal data list with the new list
            data_agreement["personal_data"] = personal_data_new_list

            # Generate data agreement model class instance
            data_agreement = DataAgreementV1Schema().load(data_agreement)

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
