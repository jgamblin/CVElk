set -e

ELASTICSEARCH_HOST='http://localhost:9200'
KIBANA_HOST='http://localhost:5601'

echo "Building nvdata docker image"
docker image build -t nvdata NVData/

echo "Brining up elasticsearch and kibana"
docker-compose up -d

echo "Waiting 45 seconds ..."
sleep 45

echo "Pushing NVD Data to Elasticsearch: $ELASTICSEARCH_HOST"
echo "Setting up dashboard on Kibana: $KIBANA_HOST"
docker run -e ELASTICSEARCH_HOST=$ELASTICSEARCH_HOST --rm --network=host --name nvdata nvdata -p -k
