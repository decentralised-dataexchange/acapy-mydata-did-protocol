from confluent_kafka import Producer
import os
import json
import logging
from enum import Enum
from dataclasses import dataclass, asdict
import typing

LOGGER = logging.getLogger(__name__)

class DataAgreementOperations(Enum):
    DACREATE = "DataAgreementCreate"
    DAUPDATE = "DataAgreementUpdate"
    DADELETE = "DataAgreementDelete"
    DAPUBLISH = "DataAgreementPublish"
    DAPERSONALDATAUPDATE = "DataAgreementPersonalDataUpdate"
    DAPERSONALDATADELETE = "DataAgreementPersonalDataDelete"


@dataclass
class KafkaMessage:
    payload: str
    org_id: str

@dataclass
class PublishEventToKafkaTopic:
    key: str
    message: str
    topic: typing.Optional[str] = None

async def publish_event_to_kafka_topic(publish_payload: PublishEventToKafkaTopic):
    kafka_server_address = os.environ.get("KAFKA_SERVER_ADDRESS", 'localhost:9092')
    igrantio_org_id = os.environ.get("IGRANTIO_ORG_ID")
    
    kafka_message = KafkaMessage(payload=publish_payload.message, org_id=igrantio_org_id)
    kafka_message_str = json.dumps(asdict(kafka_message))

    kafka_producer_configuration = {
        'bootstrap.servers': kafka_server_address,
    }
    kafka_producer = Producer(kafka_producer_configuration)

    def kafka_event_delivery_callback_handler(err: str, msg: str): 
        if err is not None: 
            log_message = f"Message delivery failed: {err}"
        else: 
            log_message = f'Message delivered to {msg.topic()}'
        LOGGER.debug(log_message)

    # Publish event to Kafka topic
    kafka_producer.produce(publish_payload.topic,key=publish_payload.key, value=kafka_message_str, callback=kafka_event_delivery_callback_handler)

    # Flush to ensure that the message is sent to the Kafka broker
    kafka_producer.flush()

async def publish_event_to_data_agreement_topic(publish_payload: PublishEventToKafkaTopic):
    publish_payload.topic = "data_agreement"
    await publish_event_to_kafka_topic(publish_payload)