import requests

headers = {
    "X-VulDB-ApiKey": "8b429e9f712ca8debdaf98adb49893e4",
    "User-Agent": "Hygiene360/1.0"
}

# Now we send as form data, not JSON
payload = {
    "search": "Adobe Acrobat",
    "details": "0"  # must be string if form
}

response = requests.post("https://vuldb.com/?api", headers=headers, data=payload)

print("Status Code:", response.status_code)
print("Response JSON:")
print(response.json())
