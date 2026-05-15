from confluent_kafka.admin import AdminClient, NewTopic

admin = AdminClient({'bootstrap.servers': 'localhost:9092'})

topics = [
    NewTopic('network-traffic', num_partitions=3, replication_factor=1)
]

futures = admin.create_topics(topics)

for name, future in futures.items():
    try:
        future.result()
        print(f'topic {name} created')
    except Exception as e:
        print(f'[ERROR] failed to create {name} : {e}')
