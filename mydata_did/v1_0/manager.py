import logging
import json

from aries_cloudagent.storage.error import StorageError
from mydata_did.v1_0.utils.regex import MyDataDID
import time
import uuid

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.connections.models.connection_record import ConnectionRecord
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.responder import BaseResponder
from aries_cloudagent.core.dispatcher import DispatcherResponder
from aries_cloudagent.transport.inbound.receipt import MessageReceipt
from aries_cloudagent.core.error import BaseError
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.indy import IndyStorage
from aries_cloudagent.wallet.indy import IndyWallet
from aries_cloudagent.wallet.base import BaseWallet, DIDInfo
from aries_cloudagent.wallet.error import WalletError, WalletNotFoundError
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager

from .messages.create_did import CreateDID
from .messages.read_did import ReadDID, ReadDIDBody
from .messages.read_did_response import ReadDIDResponse
from .messages.delete_did import DeleteDID, DeleteDIDBody
from .messages.delete_did_response import DeleteDIDResponse, DeleteDIDBodyResponse
from .messages.create_did_response import CreateDIDResponse
from .messages.problem_report import ProblemReport, ProblemReportReason
from .models.diddoc_model import MyDataDIDBody, MyDataDIDBodyResponse
from .models.registry_transaction_records import V10MyDataDIDRegistryTransaction
from .models.mydata_did_records import V10MyDataDIDRecord

from .utils.diddoc import DIDDoc
from .utils.did.mydata_did import DIDMyData
from .utils.wallet.key_type import KeyType
from .utils.verification_method import PublicKeyType


class MyDataDIDManagerError(BaseError):
    """MyDataDID manager error"""


class MyDataDIDManager:

    MYDATA_DID_RECORD_TYPE = "MyDataDID_info_record"
    MYDATA_DID_RECORD_VERIFIED_STATE = "verified"
    MYDATA_DID_RECORD_REVOKED_STATE = "revoked"

    def __init__(self, context: InjectionContext) -> None:
        self._context = context
        self._logger = logging.getLogger(__name__)

    @property
    def context(self) -> InjectionContext:
        return self._context

    async def process_problem_report_message(self, problem_report: ProblemReport, receipt: MessageReceipt):
        """
        Process problem-report DIDComm message

        Message type: mydata-did/1.0/problem-report

        Transaction records are updated to store the state.
        """
        connection_id = (
            self.context.connection_record
            and self.context.connection_record.connection_id
        )

        # create transaction record. state: received
        transaction_record: V10MyDataDIDRegistryTransaction = await V10MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": problem_report._thread_id},
            {"connection_id": connection_id}
        )
        transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
        transaction_record.error_msg = problem_report.explain
        await transaction_record.save(self.context, reason="problem-report message received")

    async def process_create_did_response_message(self, create_did_response_message: CreateDIDResponse, receipt: MessageReceipt):
        """
        Process create-did-response DIDComm message

        Message type: mydata-did/1.0/create-did-response

        Transaction records are updated to store the state.
        """
        connection_id = (
            self.context.connection_record
            and self.context.connection_record.connection_id
        )

        # create transaction record. state: received
        transaction_record: V10MyDataDIDRegistryTransaction = await V10MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": create_did_response_message._thread_id},
            {"connection_id": connection_id}
        )

        transaction_record.create_did_response_dict = create_did_response_message.serialize()
        transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_SUCCESS
        await transaction_record.save(self.context, reason="create-did-response message received")

        did_record = V10MyDataDIDRecord(did=DIDMyData.from_fingerprint(create_did_response_message.body.did_doc.did).did,
                                        state=V10MyDataDIDRecord.STATE_DID_VERIFIED)
        await did_record.save(self.context, reason="create-did-response message received")

    async def process_create_did_message(self, create_did_message: CreateDID, receipt: MessageReceipt):
        """
        Process create-did DIDComm message

        Message type: mydata-did/1.0/create-did

        A record is created for the incoming did if a verified did record doesn't exists.
        """
        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)
        from_did_string = from_did.did

        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)
        to_did_string = to_did.did

        storage: IndyStorage = await self.context.inject(BaseStorage)
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        created_time = str(int(time.time()))

        connection_id = (
            self.context.connection_record
            and self.context.connection_record.connection_id
        )

        # create transaction record. state: received
        transaction_record = V10MyDataDIDRegistryTransaction(
            thread_id=create_did_message._thread_id,
            connection_id=connection_id,
            state=V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_REQUEST_RECEIVED,
            create_did_request_dict=create_did_message.serialize(),
            record_type=V10MyDataDIDRegistryTransaction.RECORD_TYPE_CREATE
        )

        await transaction_record.save(self.context, reason="create-did message received")

        try:
            signer = await create_did_message.verify_signed_field("body", wallet, DIDMyData.from_fingerprint(create_did_message.body.did_doc.did).public_key_b58)
        except BaseModelError:
            if responder:
                # send problem-report message
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DIDDOC_SIGNATURE_VERIFICATION_FAILED.value,
                    explain="DIDDoc signature verification failed.",
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )
                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "DIDDoc signature verification failed."
                await transaction_record.save(self.context, reason="Failed to process create-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        if not (from_did_string == create_did_message.from_did and to_did_string == create_did_message.to_did):
            # send problem report
            if responder:
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DIDCOMM_MESSAGE_TO_FROM_INVALID.value,
                    explain="from and to did doesn't match recipient and sender verkeys associated with the current connection",
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )

                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "from and to did doesn't match recipient and sender verkeys associated with the current connection"
                await transaction_record.save(self.context, reason="Failed to process create-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        did_doc: DIDDoc = create_did_message.body.did_doc

        create_did_message = create_did_message.deserialize(
            create_did_message.serialize())

        # check if there is any mydata did record exists with provided did
        mydata_did_info_records = await storage.search_records(
            type_filter=MyDataDIDManager.MYDATA_DID_RECORD_TYPE,
            tag_query={
                "did": did_doc.did
            }
        ).fetch_all()

        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)
        from_did_string = from_did.did

        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)
        to_did_string = to_did.did

        # create mydata did record with state as verified
        if not mydata_did_info_records:
            record_tags = {
                "did": did_doc.did,
                "did_type": str(did_doc.did_type if did_doc.did_type else -1),
                "version": "1.0",
                "from_did": from_did_string,
                "to_did_string": to_did_string,
                "state": MyDataDIDManager.MYDATA_DID_RECORD_VERIFIED_STATE
            }
            storage_record = StorageRecord(
                MyDataDIDManager.MYDATA_DID_RECORD_TYPE,
                create_did_message.body.did_doc.to_json(),
                record_tags,
                str(uuid.uuid4())
            )

            await storage.add_record(storage_record)

            mydata_did_body = MyDataDIDBodyResponse(
                did_doc=did_doc, version="1.0")

            create_did_response = CreateDIDResponse(from_did=from_did_string,
                                                    to_did=to_did_string,
                                                    created_time=created_time,
                                                    body=mydata_did_body)
            create_did_response.assign_thread_id(
                thid=transaction_record.thread_id)

            # update transaction record. state: success
            transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_SUCCESS
            await transaction_record.save(self.context, reason="Successfully created mydata did record.")

            if responder:
                await responder.send_reply(create_did_response, connection_id=connection_id)

        else:
            # send problem report if did record exists
            if responder:
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DID_EXISTS.value,
                    explain="An existing record associated with did:mydata:{} was found".format(
                        did_doc.did),
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )

                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "An existing record associated with did:mydata:{} was found".format(
                    did_doc.did)
                await transaction_record.save(self.context, reason="Failed to process create-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

    async def send_create_did_message(self, registry_connection_record: ConnectionRecord, recipient_connection_record: ConnectionRecord):
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        storage: BaseStorage = await self.context.inject(BaseStorage)

        try:
            registry_from_did = registry_connection_record.my_did
            registry_to_did = registry_connection_record.their_did
            mydata_did = recipient_connection_record.my_did

            # from_did
            registry_from_did_info = await wallet.get_local_did(registry_from_did)
            registry_from_did_verkey = registry_from_did_info.verkey
            from_did = DIDMyData.from_public_key_b58(public_key=registry_from_did_verkey,
                                                     key_type=KeyType.ED25519)

            # to_did
            registry_to_did_record = await storage.search_records(
                ConnectionManager.RECORD_TYPE_DID_KEY, {"did": registry_to_did}
            ).fetch_single()
            registry_to_did_verkey = registry_to_did_record.value
            to_did = DIDMyData.from_public_key_b58(public_key=registry_to_did_verkey,
                                                   key_type=KeyType.ED25519)

            # mydata_did
            mydata_did_info = await wallet.get_local_did(mydata_did)
            mydata_did_verkey = mydata_did_info.verkey
            mydata_did = DIDMyData.from_public_key_b58(public_key=mydata_did_verkey,
                                                       key_type=KeyType.ED25519)

            diddoc_json = {
                "@context": DIDDoc.CONTEXT,
                "id": mydata_did.did,
                "verificationMethod": [
                    {
                        "id": f"{mydata_did.did}#1",
                        "type":  PublicKeyType.ED25519_SIG_2018.ver_type,
                        "controller": mydata_did.did,
                        "publicKeyBase58": mydata_did.fingerprint
                    }
                ],
                "authentication": [
                    {
                        "type": PublicKeyType.ED25519_SIG_2018.authn_type,
                        "publicKey": f"{mydata_did.did}#1"
                    }
                ],
                "service": [
                    {
                        "id": f"{mydata_did.did};didcomm",
                        "type": "DIDComm",
                        "priority": 0,
                        "recipientKeys": [
                            mydata_did.fingerprint
                        ],
                        "serviceEndpoint": self.context.settings.get("default_endpoint")
                    }
                ]
            }

            diddoc_str = json.dumps(diddoc_json)
            did_doc = DIDDoc.from_json(diddoc_str)
            mydata_did_body = MyDataDIDBody(did_doc=did_doc)

            request = CreateDID(from_did=from_did.did, to_did=to_did.did, created_time=str(
                int(time.time())), body=mydata_did_body)
            await request.sign_field("body", mydata_did_verkey, wallet, timestamp=time.time())

            # create a transaction record. state: sent
            transaction_record = V10MyDataDIDRegistryTransaction(
                connection_id=registry_connection_record.connection_id,
                thread_id=request._thread_id,
                their_connection_id=recipient_connection_record.connection_id,
                state=V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_REQUEST_SENT,
                create_did_request_dict=request.serialize(),
                record_type=V10MyDataDIDRegistryTransaction.RECORD_TYPE_CREATE
            )
            await transaction_record.save(
                self.context, reason="create-did request message")

            responder: BaseResponder = await self._context.inject(BaseResponder, required=False)
            if responder:
                await responder.send(request, connection_id=registry_connection_record.connection_id)

            return transaction_record

        except WalletError:
            return None

    async def process_read_did_message(self, read_did_message: ReadDID, receipt: MessageReceipt):
        """
        Process read-did DIDComm message

        Message type: mydata-did/1.0/read-did
        """
        storage: IndyStorage = await self.context.inject(BaseStorage)
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)
        from_did_string = from_did.did

        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)
        to_did_string = to_did.did

        created_time = str(int(time.time()))

        connection_id = (
            self.context.connection_record
            and self.context.connection_record.connection_id
        )

        # create transaction record (read-did request). state: received
        transaction_record = V10MyDataDIDRegistryTransaction(
            thread_id=read_did_message._thread_id,
            connection_id=connection_id,
            state=V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_REQUEST_RECEIVED,
            read_did_request_dict=read_did_message.serialize(),
            record_type=V10MyDataDIDRegistryTransaction.RECORD_TYPE_READ
        )

        await transaction_record.save(self.context, reason="read-did message received")

        if not (from_did_string == read_did_message.from_did and to_did_string == read_did_message.to_did):
            # send problem report
            if responder:
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DIDCOMM_MESSAGE_TO_FROM_INVALID.value,
                    explain="from and to did doesn't match recipient and sender verkeys associated with the current connection",
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )

                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "from and to did doesn't match recipient and sender verkeys associated with the current connection"
                await transaction_record.save(self.context, reason="Failed to process read-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        mydata_did: str = read_did_message.body.did

        try:
            if mydata_did.startswith("did:mydata"):
                mydata_did = DIDMyData.from_did(mydata_did).fingerprint
            else:
                mydata_did = DIDMyData.from_fingerprint(mydata_did).fingerprint
        except:
            # send problem report
            if responder:
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DID_INVALID.value,
                    explain="Invalid decentralised identifier provided",
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )

                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "Invalid decentralised identifier provided"
                await transaction_record.save(self.context, reason="Failed to process read-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        # fetch mydata did record by fingerprint
        try:
            mydata_did_info_records = await storage.search_records(
                type_filter=MyDataDIDManager.MYDATA_DID_RECORD_TYPE,
                tag_query={
                    "did": mydata_did
                }
            ).fetch_single()

            if mydata_did_info_records.tags.get("state") == MyDataDIDManager.MYDATA_DID_RECORD_REVOKED_STATE:
                # send problem report
                if responder:
                    problem_report = ProblemReport(
                        problem_code=ProblemReportReason.DID_REVOKED.value,
                        explain="Decentralised identifier is revoked.",
                        from_did=from_did_string,
                        to_did=to_did_string,
                        created_time=created_time
                    )

                    problem_report.assign_thread_id(
                        thid=transaction_record.thread_id)

                    # update transaction record. state: failed
                    transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                    transaction_record.error_msg = "Decentralised identifier is revoked."
                    await transaction_record.save(self.context, reason="Failed to process read-did message")

                    await responder.send_reply(problem_report, connection_id=connection_id)
            else:
                from_did: DIDMyData = DIDMyData.from_public_key_b58(
                    receipt.recipient_verkey, key_type=KeyType.ED25519)
                from_did_string = from_did.did

                to_did: DIDMyData = DIDMyData.from_public_key_b58(
                    receipt.sender_verkey, key_type=KeyType.ED25519)
                to_did_string = to_did.did

                did_doc = DIDDoc.from_json(mydata_did_info_records.value)

                # send read-did-response message
                mydata_did_body = MyDataDIDBodyResponse(
                    did_doc=did_doc, version=mydata_did_info_records.tags.get("version"))

                create_did_response = CreateDIDResponse(from_did=from_did_string,
                                                        to_did=to_did_string,
                                                        created_time=created_time,
                                                        body=mydata_did_body)
                create_did_response.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: success
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_SUCCESS
                await transaction_record.save(self.context, reason="Resolved mydata did record.")

                if responder:
                    await responder.send_reply(create_did_response, connection_id=connection_id)
        except StorageError:
            # send problem report
            problem_report = ProblemReport(
                problem_code=ProblemReportReason.DID_NOT_FOUND.value,
                explain="Record associated with MyData decentralised identifier : {} was not found".format(
                    DIDMyData.from_fingerprint(mydata_did).did),
                from_did=from_did_string,
                to_did=to_did_string,
                created_time=created_time
            )

            problem_report.assign_thread_id(
                thid=transaction_record.thread_id)

            # update transaction record. state: failed
            transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
            transaction_record.error_msg = "Record associated with MyData decentralised identifier : {} was not found".format(
                DIDMyData.from_fingerprint(mydata_did).did)
            await transaction_record.save(self.context, reason="Failed to process read-did message")

            await responder.send_reply(problem_report, connection_id=connection_id)

    async def process_read_did_response_message(self, read_did_response_message: ReadDIDResponse, receipt: MessageReceipt):
        """
        Process read-did-response DIDComm message

        Message type: mydata-did/1.0/read-did-response
        """
        connection_id = (
            self.context.connection_record
            and self.context.connection_record.connection_id
        )

        # create transaction record. state: received
        transaction_record: V10MyDataDIDRegistryTransaction = await V10MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": read_did_response_message._thread_id},
            {"connection_id": connection_id}
        )

        transaction_record.read_did_response_dict = read_did_response_message.serialize()
        transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_SUCCESS
        await transaction_record.save(self.context, reason="read-did-response message received")

    async def send_read_did_message(self, registry_connection_record: ConnectionRecord, did: str):
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        storage: BaseStorage = await self.context.inject(BaseStorage)

        try:
            registry_from_did = registry_connection_record.my_did
            registry_to_did = registry_connection_record.their_did

            # from_did
            registry_from_did_info = await wallet.get_local_did(registry_from_did)
            registry_from_did_verkey = registry_from_did_info.verkey
            from_did = DIDMyData.from_public_key_b58(public_key=registry_from_did_verkey,
                                                     key_type=KeyType.ED25519)

            # to_did
            registry_to_did_record = await storage.search_records(
                ConnectionManager.RECORD_TYPE_DID_KEY, {"did": registry_to_did}
            ).fetch_single()
            registry_to_did_verkey = registry_to_did_record.value
            to_did = DIDMyData.from_public_key_b58(public_key=registry_to_did_verkey,
                                                   key_type=KeyType.ED25519)

            read_did_body = ReadDIDBody(did=did)

            request = ReadDID(from_did=from_did.did, to_did=to_did.did, created_time=str(
                int(time.time())), body=read_did_body)

            # create a transaction record. state: sent
            transaction_record = V10MyDataDIDRegistryTransaction(
                connection_id=registry_connection_record.connection_id,
                thread_id=request._thread_id,
                state=V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_REQUEST_SENT,
                read_did_request_dict=request.serialize(),
                record_type=V10MyDataDIDRegistryTransaction.RECORD_TYPE_READ
            )
            await transaction_record.save(
                self.context, reason="read-did request message")

            responder: BaseResponder = await self._context.inject(BaseResponder, required=False)
            if responder:
                await responder.send(request, connection_id=registry_connection_record.connection_id)

            return transaction_record

        except WalletError:
            return None

    async def process_delete_did_message(self, delete_did_message: DeleteDID, receipt: MessageReceipt):
        """
        Process delete-did DIDComm message

        Message type: mydata-did/1.0/delete-did
        """

        from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519)
        from_did_string = from_did.did

        to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519)
        to_did_string = to_did.did

        storage: IndyStorage = await self.context.inject(BaseStorage)
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        responder: DispatcherResponder = await self.context.inject(BaseResponder, required=False)

        created_time = str(int(time.time()))

        connection_id = (
            self.context.connection_record
            and self.context.connection_record.connection_id
        )

        # create transaction record. state: received
        transaction_record = V10MyDataDIDRegistryTransaction(
            thread_id=delete_did_message._thread_id,
            connection_id=connection_id,
            state=V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_REQUEST_RECEIVED,
            delete_did_request_dict=delete_did_message.serialize(),
            record_type=V10MyDataDIDRegistryTransaction.RECORD_TYPE_DELETE
        )

        await transaction_record.save(self.context, reason="delete-did message received")

        mydata_did: str = delete_did_message.body.did

        try:
            if mydata_did.startswith("did:mydata"):
                mydata_did = DIDMyData.from_did(mydata_did).fingerprint
            else:
                mydata_did = DIDMyData.from_fingerprint(mydata_did).fingerprint
        except:
            # send problem report
            if responder:
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DID_INVALID.value,
                    explain="Invalid decentralised identifier provided",
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )

                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "Invalid decentralised identifier provided"
                await transaction_record.save(self.context, reason="Failed to process delete-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        try:
            signer = await delete_did_message.verify_signed_field("body", wallet, DIDMyData.from_fingerprint(mydata_did).public_key_b58)
        except BaseModelError:
            if responder:
                # send problem-report message
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DIDDOC_SIGNATURE_VERIFICATION_FAILED.value,
                    explain="DIDDoc signature verification failed.",
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )
                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "DIDDoc signature verification failed."
                await transaction_record.save(self.context, reason="Failed to process create-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        if not (from_did_string == delete_did_message.from_did and to_did_string == delete_did_message.to_did):
            # send problem report
            if responder:
                problem_report = ProblemReport(
                    problem_code=ProblemReportReason.DIDCOMM_MESSAGE_TO_FROM_INVALID.value,
                    explain="from and to did doesn't match recipient and sender verkeys associated with the current connection",
                    from_did=from_did_string,
                    to_did=to_did_string,
                    created_time=created_time
                )

                problem_report.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: failed
                transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
                transaction_record.error_msg = "from and to did doesn't match recipient and sender verkeys associated with the current connection"
                await transaction_record.save(self.context, reason="Failed to process delete-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        # fetch mydata did record by fingerprint
        try:
            mydata_did_info_records = await storage.search_records(
                type_filter=MyDataDIDManager.MYDATA_DID_RECORD_TYPE,
                tag_query={
                    "did": mydata_did
                }
            ).fetch_single()

            mydata_did_info_records.tags["state"] = MyDataDIDManager.MYDATA_DID_RECORD_REVOKED_STATE

            await storage.update_record_tags(mydata_did_info_records, tags=mydata_did_info_records.tags)

            from_did: DIDMyData = DIDMyData.from_public_key_b58(
                receipt.recipient_verkey, key_type=KeyType.ED25519)
            from_did_string = from_did.did

            to_did: DIDMyData = DIDMyData.from_public_key_b58(
                receipt.sender_verkey, key_type=KeyType.ED25519)
            to_did_string = to_did.did

            # send delete-did-response message
            delete_did_body = DeleteDIDBodyResponse(status="revoked", did=DIDMyData.from_fingerprint(mydata_did).did)

            delete_did_response = DeleteDIDResponse(from_did=from_did_string,
                                                    to_did=to_did_string,
                                                    created_time=created_time,
                                                    body=delete_did_body)
            delete_did_response.assign_thread_id(
                thid=transaction_record.thread_id)

            # update transaction record. state: success
            transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_SUCCESS
            await transaction_record.save(self.context, reason="Revoked mydata did.")

            if responder:
                await responder.send_reply(delete_did_response, connection_id=connection_id)
        except StorageError:
            # send problem report
            problem_report = ProblemReport(
                problem_code=ProblemReportReason.DID_NOT_FOUND.value,
                explain="Record associated with MyData decentralised identifier : {} was not found".format(
                    DIDMyData.from_fingerprint(mydata_did).did),
                from_did=from_did_string,
                to_did=to_did_string,
                created_time=created_time
            )

            problem_report.assign_thread_id(
                thid=transaction_record.thread_id)

            # update transaction record. state: failed
            transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_FAILED
            transaction_record.error_msg = "Record associated with MyData decentralised identifier : {} was not found".format(
                DIDMyData.from_fingerprint(mydata_did).did)
            await transaction_record.save(self.context, reason="Failed to process delete-did message")

            await responder.send_reply(problem_report, connection_id=connection_id)

    async def process_delete_did_response_message(self, delete_did_response_message: DeleteDIDResponse, receipt: MessageReceipt):
        """
        Process delete-did-response DIDComm message

        Message type: mydata-did/1.0/delete-did-response
        """
        connection_id = (
            self.context.connection_record
            and self.context.connection_record.connection_id
        )

        # create transaction record. state: received
        transaction_record: V10MyDataDIDRegistryTransaction = await V10MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": delete_did_response_message._thread_id},
            {"connection_id": connection_id}
        )

        transaction_record.delete_did_response_dict = delete_did_response_message.serialize()
        transaction_record.state = V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_SUCCESS
        await transaction_record.save(self.context, reason="delete-did-response message received")

        did_record = V10MyDataDIDRecord(did=DIDMyData.from_fingerprint(delete_did_response_message.body.did).did,
                                        state=V10MyDataDIDRecord.STATE_DID_VERIFIED)
        await did_record.save(self.context, reason="create-did-response message received")

    async def send_delete_did_message(self, registry_connection_record: ConnectionRecord, did: str):
        wallet: IndyWallet = await self.context.inject(BaseWallet)
        storage: BaseStorage = await self.context.inject(BaseStorage)

        try:
            registry_from_did = registry_connection_record.my_did
            registry_to_did = registry_connection_record.their_did

            # from_did
            registry_from_did_info = await wallet.get_local_did(registry_from_did)
            registry_from_did_verkey = registry_from_did_info.verkey
            from_did = DIDMyData.from_public_key_b58(public_key=registry_from_did_verkey,
                                                     key_type=KeyType.ED25519)

            # to_did
            registry_to_did_record = await storage.search_records(
                ConnectionManager.RECORD_TYPE_DID_KEY, {"did": registry_to_did}
            ).fetch_single()
            registry_to_did_verkey = registry_to_did_record.value
            to_did = DIDMyData.from_public_key_b58(public_key=registry_to_did_verkey,
                                                   key_type=KeyType.ED25519)

            try:
                if did.startswith("did:mydata"):
                    mydata_did = DIDMyData.from_did(did).fingerprint
                else:
                    mydata_did = DIDMyData.from_fingerprint(did).fingerprint
            except:
                return None

            try:
                to_be_revoked_did_record = await wallet.get_local_did_for_verkey(DIDMyData.from_fingerprint(mydata_did).public_key_b58)
            except WalletNotFoundError:
                return None

            delete_did_body = DeleteDIDBody(did=did)

            request = DeleteDID(from_did=from_did.did, to_did=to_did.did, created_time=str(
                int(time.time())), body=delete_did_body)
            await request.sign_field("body", to_be_revoked_did_record.verkey, wallet, timestamp=time.time())

            # create a transaction record. state: sent
            transaction_record = V10MyDataDIDRegistryTransaction(
                connection_id=registry_connection_record.connection_id,
                thread_id=request._thread_id,
                state=V10MyDataDIDRegistryTransaction.STATE_CREATE_DID_CREATE_REQUEST_SENT,
                delete_did_request_dict=request.serialize(),
                record_type=V10MyDataDIDRegistryTransaction.RECORD_TYPE_DELETE
            )
            await transaction_record.save(
                self.context, reason="delete-did request message")

            responder: BaseResponder = await self._context.inject(BaseResponder, required=False)
            if responder:
                await responder.send(request, connection_id=registry_connection_record.connection_id)

            return transaction_record

        except WalletError:
            return None
