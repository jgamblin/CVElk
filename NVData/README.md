# Running application standalone

## Elastic Cloud Setup

Generate and API key to push the data to cloud

Cloud -> Deployments -> <DEPLOYMENT-NAME> -> Elasticsearch -> API console

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

