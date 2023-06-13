from confluent_kafka import Producer
import os
import json
from logging import Logger
from enum import Enum
# from mydata_did.v1_0.manager import ADAManager

class DataAgreementOperations(Enum):
    DACREATE = "DataAgreementCreate"
    DAUPDATE = "DataAgreementUpdate"
    DADELETE = "DataAgreementDelete"
    DAPUBLISH = "DataAgreementPublish"
    DAPERSONALDATAUPDATE = "DataAgreementPersonalDataUpdate"
    DAPERSONALDATADELETE = "DataAgreementPersonalDataDelete"

async def publish_event_to_kafka_topic(key: str, message: str, topic: str, logger: Logger):
    kafka_server_address = os.environ.get("KAFKA_SERVER_ADDRESS", 'localhost:9092')
    # Fetch iGrant.io config
    # igrantio_config =await ada_manager.fetch_igrantio_config_from_os_environ()
    igrantio_org_id = os.environ.get("IGRANTIO_ORG_ID")
    data = json.loads(message)
    data['igrantio_org_id'] = igrantio_org_id

    message_with_org_id = json.dumps(data)

    kafka_producer_configuration = {
        'bootstrap.servers': kafka_server_address,
    }
    kafka_producer = Producer(kafka_producer_configuration)

    def kafka_event_delivery_callback_handler(err: str, msg: str): 
        if err is not None: 
            log_message = f"Message delivery failed: {err}"
        else: 
            log_message = f'Message delivered to {msg.topic()} [{msg.partition()}] partition'
        logger.debug(log_message)

    # Publish event to Kafka topic
    kafka_producer.produce(topic,key=key, value=message_with_org_id, callback=kafka_event_delivery_callback_handler)

    # Wait for the message to be delivered
    kafka_producer.flush()

async def publish_event_to_data_agreement_topic(key: str, message: str, logger: Logger):
    topic = "data_agreement"
    await publish_event_to_kafka_topic(key, message, topic, logger)