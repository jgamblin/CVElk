set -e

echo "Building nvdata docker image"
docker image build -t nvdata NVData/

echo "Brining up elasticsearch and kibana"
docker-compose up -d

echo "Waiting 45 seconds ..."
sleep 45

echo "Running nvdata docker container to populate elasticsearch"
docker run --rm --network=host --name nvdata nvdata

echo "Setting Kibana theme to darkMode"
curl -f -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: kibana" \
        "http://localhost:5601/api/kibana/settings/theme:darkMode" \
        -d '{ "value": true}'

echo "Creating dashboard on Kibana"
curl -X POST "localhost:5601/api/saved_objects/_import?createNewCopies=true" -H "kbn-xsrf: true" --form file=@Dashboard/dashboard.ndjson
