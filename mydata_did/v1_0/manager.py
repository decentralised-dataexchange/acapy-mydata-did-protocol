import json
import logging
import time
import typing

import aiohttp
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.connections.models.connection_target import ConnectionTarget
from aries_cloudagent.core.dispatcher import DispatcherResponder
from aries_cloudagent.core.error import BaseError
from aries_cloudagent.messaging.decorators.transport_decorator import TransportDecorator
from aries_cloudagent.messaging.responder import BaseResponder
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager
from aries_cloudagent.storage.base import BaseStorage, StorageRecord
from aries_cloudagent.storage.error import StorageDuplicateError, StorageNotFoundError
from aries_cloudagent.storage.indy import IndyStorage
from aries_cloudagent.transport.inbound.receipt import MessageReceipt
from aries_cloudagent.transport.pack_format import PackWireFormat
from aries_cloudagent.transport.wire_format import BaseWireFormat
from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.indy import IndyWallet
from mydata_did.v1_0.messages.problem_report import (
    MyDataDIDProblemReportMessage,
    MyDataDIDProblemReportMessageReason,
)
from mydata_did.v1_0.messages.read_did import ReadDIDMessage, ReadDIDMessageBody
from mydata_did.v1_0.messages.read_did_response import (
    ReadDIDResponseMessage,
    ReadDIDResponseMessageSchema,
)
from mydata_did.v1_0.models.diddoc_model import MyDataDIDDoc, MyDataDIDResponseBody
from mydata_did.v1_0.utils.did.mydata_did import DIDMyData
from mydata_did.v1_0.utils.wallet.key_type import KeyType


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
    RECORD_TYPE_TEMPORARY_DATA_AGREEMENT_PERSONAL_DATA = (
        "temporary_data_agreement_personal_data"
    )

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

    async def process_read_did_message(
        self, read_did_message: ReadDIDMessage, receipt: MessageReceipt
    ):
        """
        Process read-did DIDComm message
        """

        # Storage instance from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        # Responder instance from context
        responder: DispatcherResponder = await self.context.inject(
            BaseResponder, required=False
        )

        # From and To DIDs of the recieved message
        create_did_message_from_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.sender_verkey, key_type=KeyType.ED25519
        )
        create_did_message_to_did: DIDMyData = DIDMyData.from_public_key_b58(
            receipt.recipient_verkey, key_type=KeyType.ED25519
        )

        # From and To DIDs for the response messages
        response_message_from_did = create_did_message_to_did
        response_message_to_did = create_did_message_from_did

        mydata_did_registry_did_info_record = None
        try:

            # Fetch DID from wallet
            mydata_did_registry_did_info_record = await storage.search_records(
                type_filter=ADAManager.RECORD_TYPE_MYDATA_DID_REGISTRY_DID_INFO,
                tag_query={"did": read_did_message.body.did},
            ).fetch_single()

        except (StorageNotFoundError, StorageDuplicateError):
            # Send problem-report message.

            mydata_did_problem_report = MyDataDIDProblemReportMessage(
                problem_code=MyDataDIDProblemReportMessageReason.DID_NOT_FOUND.value,
                explain="DID not found.",
                from_did=response_message_from_did.did,
                to_did=response_message_to_did.did,
                created_time=round(time.time() * 1000),
            )

            # Assign thread id
            mydata_did_problem_report.assign_thread_id(thid=read_did_message._id)

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
                    mydata_did_registry_did_info_record.value
                ),
                version=mydata_did_registry_did_info_record.tags.get("version"),
                status=mydata_did_registry_did_info_record.tags.get("status"),
            ),
        )

        # Assign thread id
        read_did_response_message.assign_thread_id(thid=read_did_message._id)

        if responder:
            await responder.send_reply(read_did_response_message)

    async def process_read_did_response_message(
        self, read_did_response_message: ReadDIDResponseMessage, receipt: MessageReceipt
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

    async def store_data_agreement_instance_metadata(
        self,
        *,
        data_agreement_id: str = None,
        data_agreement_template_id: str = None,
        method_of_use: str = None,
        data_exchange_record_id: str = None,
    ) -> None:
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
                "data_exchange_record_id": data_exchange_record_id,
            },
        )

        await storage.add_record(data_instance_metadata_record)

    async def delete_data_agreement_instance_metadata(
        self, *, tag_query: dict = None
    ) -> None:
        """Delete data agreement instance metadata"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        storage_records = await storage.search_records(
            type_filter=self.RECORD_TYPE_DATA_AGREEMENT_INSTANCE_METADATA,
            tag_query=tag_query,
        ).fetch_all()

        for storage_record in storage_records:
            await storage.delete_record(storage_record)

    async def query_data_agreement_instance_metadata(
        self, *, tag_query: dict = None
    ) -> typing.List[StorageRecord]:
        """Query data agreement instance metadata"""

        # Fetch storage from context
        storage: IndyStorage = await self.context.inject(BaseStorage)

        storage_records = await storage.search_records(
            type_filter=self.RECORD_TYPE_DATA_AGREEMENT_INSTANCE_METADATA,
            tag_query=tag_query,
        ).fetch_all()

        return storage_records

    async def resolve_remote_mydata_did(
        self, *, mydata_did: str
    ) -> MyDataDIDResponseBody:
        """Resolve remote MyData DID"""

        # Initialize DID MyData
        mydata_did = DIDMyData.from_did(mydata_did)

        # Fetch wallet from context
        wallet: IndyWallet = await self.context.inject(BaseWallet)

        # Get pack format from context
        pack_format: PackWireFormat = await self.context.inject(BaseWireFormat)

        # Fetch connection record marked as MyData DID registry
        (
            connection_record,
            err,
        ) = await self.fetch_mydata_did_registry_connection_record()
        if err:
            raise ADAManagerError(
                "Failed to fetch MyData DID registry connection record"
            )

        # Construct read-did message
        # from_did
        pairwise_local_did_record = await wallet.get_local_did(connection_record.my_did)
        from_did = DIDMyData.from_public_key_b58(
            pairwise_local_did_record.verkey, key_type=KeyType.ED25519
        )

        # to_did
        to_did = DIDMyData.from_public_key_b58(
            connection_record.their_did, key_type=KeyType.ED25519
        )

        # Create read-did message
        read_did_message = ReadDIDMessage(
            from_did=from_did.did,
            to_did=to_did.did,
            created_time=round(time.time() * 1000),
            body=ReadDIDMessageBody(did=mydata_did.did),
        )

        # Add transport decorator
        read_did_message._decorators["transport"] = TransportDecorator(
            return_route="all"
        )

        # Initialise connection manager
        connection_manager = ConnectionManager(self.context)

        # Fetch connection targets
        connection_targets = await connection_manager.fetch_connection_targets(
            connection_record
        )

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

        headers = {"Content-Type": "application/ssi-agent-wire"}
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.post(
                connection_target.endpoint, data=packed_message
            ) as response:
                if response.status != 200:
                    raise ADAManagerError(
                        f"HTTP request failed with status code {response.status}"
                    )

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
                        f"Problem report received with problem-code:{message_json['problem-code']} and reason: {message_json['explain']}"
                    )

                if "read-did-response" in message_json["@type"]:
                    read_did_response_message: ReadDIDResponseMessage = (
                        ReadDIDResponseMessageSchema().load(message_json)
                    )

                    if read_did_response_message.body.status == "revoked":
                        raise ADAManagerError(f"MyData DID {mydata_did.did} is revoked")

                    return read_did_response_message.body
