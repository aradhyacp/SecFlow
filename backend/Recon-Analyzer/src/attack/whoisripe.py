import requests

def whoisripe(query:str):
    url: str = "https://rest.db.ripe.net/search.json"

    params = {"query-string": query}

    response = requests.get(url, params=params)
    response.raise_for_status()

    return response.json()
    
print(whoisripe("google.com"))