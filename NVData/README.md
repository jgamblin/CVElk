## Elastic Cloud Setup

1) Get your Elastic Cloud ID from [https://cloud.elastic.co/](https://cloud.elastic.co/)
   1) Home -> Settings Wheel beside deployment name -> Cloud ID
2) Generate an Elastic Cloud API Key through the API console (use the template JSON below)
   1) Cloud -> Deployments -> <DEPLOYMENT-NAME> -> Elasticsearch -> API console
   2) Take note of the API ID and API Key

```JSON
{
 "name": "python-apikey",
 "role_descriptors": {
   "python_read_write": {
     "cluster": ["manage_index_templates", "cves"],
     "index": [
       {
         "names": ["*"],
         "privileges": ["create_index", "write", "read", "manage"]
       }
     ]
   }
 }
}
```

## Installing and running

You can either run using Python or use the docker container.

### Using Docker

You can supply environment variables to the docker image that'll be picked up by the Python app

```bash
# Build the docker image
docker image build -t nvdata NVData/
# Set 3 environment variables on your host machine
# 1) ELASTICSEARCH_CLOUD_ID
# 2) ELASTICSEARCH_API_ID
# 3) ELASTICSEARCH_API_KEY
# e.g. create a file /etc/profile.d/elastic.sh, set the variables and run source /etc/profile.d/elastic.sh
# Push data to an Elastic Cloud instance
docker run -e ELASTICSEARCH_CLOUD_ID=$ELASTICSEARCH_CLOUD_ID \
      -e ELASTICSEARCH_API_ID=$ELASTICSEARCH_API_ID \
      -e ELASTICSEARCH_API_KEY=$ELASTICSEARCH_API_KEY \
      --rm --network=host --name nvdata nvdata -c -p
```

### Using Python

The python app uses a `config.yml` file which can be populated with credentials

```bash
# Install Poetry https://python-poetry.org/docs/
curl -sSL https://install.python-poetry.org | python3 -
# Make sure you're in the right directory
cd CVElk/NVData/app
# Create a virtual environment
poetry shell
# Install the dependencies 
poetry install
# Rename config.example.yml to config.yml
# Populate it with required fields
# Download the NVD catalog, extract the files and push them to a cloud instance
python3 main.py -c -d -e -p

# Alternatively push it to a local Elasticseach instance (-k will set kibana to dark theme and setup the index and dashboard)
python3 main.py -d -e -p -k
```

