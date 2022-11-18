## Usage

```bash
# Install Poetry https://python-poetry.org/docs/
curl -sSL https://install.python-poetry.org | python3 -
# Create a virtual environment
poetry shell
# Install the dependencies 
poetry install
```

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