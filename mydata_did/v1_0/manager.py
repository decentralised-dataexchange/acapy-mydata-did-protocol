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

from .messages.create_did import CreateDID
from .messages.read_did import ReadDID, ReadDIDBody
from .messages.read_did_response import ReadDIDResponse
from .messages.delete_did import DeleteDID, DeleteDIDBody
from .messages.delete_did_response import DeleteDIDResponse, DeleteDIDBodyResponse
from .messages.create_did_response import CreateDIDResponse
from .messages.problem_report import ProblemReport, ProblemReportReason
from .messages.read_data_agreement import ReadDataAgreement
from .messages.read_data_agreement_response import ReadDataAgreementResponse

from .models.data_agreement_model import DataAgreementV1, DataAgreementPersonalData
from .models.read_data_agreement_model import ReadDataAgreementBody
from .models.diddoc_model import MyDataDIDBody, MyDataDIDBodyResponse
from .models.mydata_did_records import MyDataDIDRecord
from .models.read_data_agreement_response_model import ReadDataAgreementResponseBody
from .models.exchange_records.registry_transaction_record import MyDataDIDRegistryTransaction
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

    MYDATA_DID_RECORD_TYPE = "mydata_info_record"
    MYDATA_DID_RECORD_VERIFIED_STATE = "verified"
    MYDATA_DID_RECORD_REVOKED_STATE = "revoked"

    DATA_AGREEMENT_RECORD_TYPE = "dataagreement_record"

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
        transaction_record: MyDataDIDRegistryTransaction = await MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": problem_report._thread_id},
            {"connection_id": connection_id}
        )
        transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
        transaction_record: MyDataDIDRegistryTransaction = await MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": create_did_response_message._thread_id},
            {"connection_id": connection_id}
        )

        transaction_record.create_did_response_dict = create_did_response_message.serialize()
        transaction_record.state = MyDataDIDRegistryTransaction.STATE_SUCCESS
        await transaction_record.save(self.context, reason="create-did-response message received")

        did_record = MyDataDIDRecord(did=DIDMyData.from_fingerprint(create_did_response_message.body.did_doc.did).did,
                                     state=MyDataDIDRecord.STATE_DID_VERIFIED)
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
        transaction_record = MyDataDIDRegistryTransaction(
            thread_id=create_did_message._thread_id,
            connection_id=connection_id,
            state=MyDataDIDRegistryTransaction.STATE_RECEIVED,
            create_did_request_dict=create_did_message.serialize(),
            record_type=MyDataDIDRegistryTransaction.RECORD_TYPE_CREATE
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
                transaction_record.error_msg = "from and to did doesn't match recipient and sender verkeys associated with the current connection"
                await transaction_record.save(self.context, reason="Failed to process create-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        did_doc: DIDDoc = create_did_message.body.did_doc

        create_did_message = create_did_message.deserialize(
            create_did_message.serialize())

        # check if there is any mydata did record exists with provided did
        mydata_did_info_records = await storage.search_records(
            type_filter=ADAManager.MYDATA_DID_RECORD_TYPE,
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
                "state": ADAManager.MYDATA_DID_RECORD_VERIFIED_STATE
            }
            storage_record = StorageRecord(
                ADAManager.MYDATA_DID_RECORD_TYPE,
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
            transaction_record.state = MyDataDIDRegistryTransaction.STATE_SUCCESS
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
            transaction_record = MyDataDIDRegistryTransaction(
                connection_id=registry_connection_record.connection_id,
                thread_id=request._thread_id,
                their_connection_id=recipient_connection_record.connection_id,
                state=MyDataDIDRegistryTransaction.STATE_SENT,
                create_did_request_dict=request.serialize(),
                record_type=MyDataDIDRegistryTransaction.RECORD_TYPE_CREATE
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
        transaction_record = MyDataDIDRegistryTransaction(
            thread_id=read_did_message._thread_id,
            connection_id=connection_id,
            state=MyDataDIDRegistryTransaction.STATE_RECEIVED,
            read_did_request_dict=read_did_message.serialize(),
            record_type=MyDataDIDRegistryTransaction.RECORD_TYPE_READ
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
                transaction_record.error_msg = "Invalid decentralised identifier provided"
                await transaction_record.save(self.context, reason="Failed to process read-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        # fetch mydata did record by fingerprint
        try:
            mydata_did_info_records = await storage.search_records(
                type_filter=ADAManager.MYDATA_DID_RECORD_TYPE,
                tag_query={
                    "did": mydata_did
                }
            ).fetch_single()

            if mydata_did_info_records.tags.get("state") == ADAManager.MYDATA_DID_RECORD_REVOKED_STATE:
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
                    transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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

                read_did_response = ReadDIDResponse(from_did=from_did_string,
                                                    to_did=to_did_string,
                                                    created_time=created_time,
                                                    body=mydata_did_body)
                read_did_response.assign_thread_id(
                    thid=transaction_record.thread_id)

                # update transaction record. state: success
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_SUCCESS
                await transaction_record.save(self.context, reason="Resolved mydata did record.")

                if responder:
                    await responder.send_reply(read_did_response, connection_id=connection_id)
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
            transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
        transaction_record: MyDataDIDRegistryTransaction = await MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": read_did_response_message._thread_id},
            {"connection_id": connection_id}
        )

        transaction_record.read_did_response_dict = read_did_response_message.serialize()
        transaction_record.state = MyDataDIDRegistryTransaction.STATE_SUCCESS
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
            transaction_record = MyDataDIDRegistryTransaction(
                connection_id=registry_connection_record.connection_id,
                thread_id=request._thread_id,
                state=MyDataDIDRegistryTransaction.STATE_SENT,
                read_did_request_dict=request.serialize(),
                record_type=MyDataDIDRegistryTransaction.RECORD_TYPE_READ
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
        transaction_record = MyDataDIDRegistryTransaction(
            thread_id=delete_did_message._thread_id,
            connection_id=connection_id,
            state=MyDataDIDRegistryTransaction.STATE_RECEIVED,
            delete_did_request_dict=delete_did_message.serialize(),
            record_type=MyDataDIDRegistryTransaction.RECORD_TYPE_DELETE
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
                transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
                transaction_record.error_msg = "from and to did doesn't match recipient and sender verkeys associated with the current connection"
                await transaction_record.save(self.context, reason="Failed to process delete-did message")

                await responder.send_reply(problem_report, connection_id=connection_id)

        # fetch mydata did record by fingerprint
        try:
            mydata_did_info_records = await storage.search_records(
                type_filter=ADAManager.MYDATA_DID_RECORD_TYPE,
                tag_query={
                    "did": mydata_did
                }
            ).fetch_single()

            mydata_did_info_records.tags["state"] = ADAManager.MYDATA_DID_RECORD_REVOKED_STATE

            await storage.update_record_tags(mydata_did_info_records, tags=mydata_did_info_records.tags)

            from_did: DIDMyData = DIDMyData.from_public_key_b58(
                receipt.recipient_verkey, key_type=KeyType.ED25519)
            from_did_string = from_did.did

            to_did: DIDMyData = DIDMyData.from_public_key_b58(
                receipt.sender_verkey, key_type=KeyType.ED25519)
            to_did_string = to_did.did

            # send delete-did-response message
            delete_did_body = DeleteDIDBodyResponse(
                status="revoked", did=DIDMyData.from_fingerprint(mydata_did).did)

            delete_did_response = DeleteDIDResponse(from_did=from_did_string,
                                                    to_did=to_did_string,
                                                    created_time=created_time,
                                                    body=delete_did_body)
            delete_did_response.assign_thread_id(
                thid=transaction_record.thread_id)

            # update transaction record. state: success
            transaction_record.state = MyDataDIDRegistryTransaction.STATE_SUCCESS
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
            transaction_record.state = MyDataDIDRegistryTransaction.STATE_FAILED
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
        transaction_record: MyDataDIDRegistryTransaction = await MyDataDIDRegistryTransaction.retrieve_by_tag_filter(
            self.context,
            {"thread_id": delete_did_response_message._thread_id},
            {"connection_id": connection_id}
        )

        transaction_record.delete_did_response_dict = delete_did_response_message.serialize()
        transaction_record.state = MyDataDIDRegistryTransaction.STATE_SUCCESS
        await transaction_record.save(self.context, reason="delete-did-response message received")

        did_record = MyDataDIDRecord(did=DIDMyData.from_fingerprint(delete_did_response_message.body.did).did,
                                     state=MyDataDIDRecord.STATE_DID_VERIFIED)
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
            transaction_record = MyDataDIDRegistryTransaction(
                connection_id=registry_connection_record.connection_id,
                thread_id=request._thread_id,
                state=MyDataDIDRegistryTransaction.STATE_SENT,
                delete_did_request_dict=request.serialize(),
                record_type=MyDataDIDRegistryTransaction.RECORD_TYPE_DELETE
            )
            await transaction_record.save(
                self.context, reason="delete-did request message")

            responder: BaseResponder = await self._context.inject(BaseResponder, required=False)
            if responder:
                await responder.send(request, connection_id=registry_connection_record.connection_id)

            return transaction_record

        except WalletError:
            return None

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
            parent_message_id=data_agreement_message._id,
            message_family=DataAgreementCRUDDIDCommTransaction.MESSAGE_FAMILY_READ_DATA_AGREEMENT,
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
                {"parent_message_id": read_data_agreement_response_message._thread_id}
            )
            # Update the txn record with response message
            da_crud_didcomm_txn.messages_list.append(
                read_data_agreement_response_message.to_json())
            await da_crud_didcomm_txn.save(self.context)

        except (StorageNotFoundError, StorageDuplicateError):
            pass

    async def create_and_store_data_agreement_in_wallet(self, data_agreement: DataAgreementV1) -> DataAgreementV1Record:
        """
        Create and store a data agreement in the wallet.
        """

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
            
            self._logger.info(f"Query data agreements in wallet with tag_filter: {tag_filter}")

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

    async def update_data_agreement_in_wallet(self, data_agreement_id: str, data_agreement: DataAgreementV1) -> DataAgreementV1Record:
        """
        Update data agreement in the wallet.
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

            # Update the published_flag status for the old data agreement record
            old_data_agreement_record.published_flag = "False"

            # Update the old data agreement record
            await old_data_agreement_record.save(self.context)

            # Set the data agreement version for the new data agreement (increment by 1)
            data_agreement.data_agreement_template_version = old_data_agreement_record.data_agreement.get("template_version") + 1
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
            personal_data_category_list =  [personal_data_record.attribute_category for personal_data_record in personal_data_records]

            # Remove duplicates
            personal_data_category_list = list(set(personal_data_category_list))

            return personal_data_category_list
        except StorageSearchError as e:
            # Raise an error
            raise ADAManagerError(
                f"Failed to fetch all data agreements from wallet: {e}"
            )


