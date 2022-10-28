docker image build -t nvdata NVData/

docker-compose up -d

sleep 45

docker run --network=host nvdata

curl -X POST "localhost:5601/api/data_views/data_view" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d'
{
  "data_view": {
    "title": "cves*",
    "name": "CVE",
    "timeFieldName": "published",
    "runtimeFieldMap": "{}"
    }
}
'

curl -f -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: kibana" \
        "http://localhost:5601/api/kibana/settings/theme:darkMode" \
        -d '{ "value": true}'


curl -X POST "localhost:5601/api/saved_objects/_import?createNewCopies=true" -H "kbn-xsrf: true" --form file=@Dashboard/dashboard.ndjson