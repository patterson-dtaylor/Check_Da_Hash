import requests
import json
import hashlib

# Hash Checker
def hash_checker(path_to_file):
    with open(path_to_file, 'rb') as f:
        file_hash = hashlib.md5()
        while chunck := f.read(8192):
            file_hash.update(chunck)
    return file_hash.hexdigest()

# Variables
file = input("What file would you like to check? (Please use full path.) ")
file_hash = hash_checker(file)
base_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
headers = { 'x-apikey': '' }
response = requests.get(base_url, headers=headers)
content = response.content
info = json.loads(content)
data = info["data"]
attributes = data["attributes"]
classifcation = attributes["popular_threat_classification"]
category = classifcation["popular_threat_category"]
threat_type = category[0]["value"]
popular_names = classifcation["popular_threat_name"]
name = popular_names[0]["value"]
stats = attributes["last_analysis_stats"]
score = stats["malicious"]


print(f"The hash checked has a score of: {score}/70")
print(f"The hash is considered a: {threat_type}")
print(f"The name of the threat is: {name}")