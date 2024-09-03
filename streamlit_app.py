from urllib.parse import urlparse
import json
import base64
import streamlit as st
import requests


def trojanvless(link):
    parsed = urlparse(link)
    netloc = parsed.netloc
    ipport = netloc.split("@")[1]
    return ipport.split(":")[0]


def vmess(link):
    inf = link.replace("vmess://", "")
    decoded = base64.b64decode(inf).decode()
    data = json.loads(decoded)
    return data["add"]


def ss(link):
    inf = link.replace("ss://", "")
    inf = inf.split("#")[0]
    decoded = base64.b64decode(inf).decode()
    ipport = decoded.split("@")[1]
    return ipport.split(":")[0]


def get_info(ip):
    return requests.get(f"http://ipinfo.io/{ip}/json", timeout=50).json()


url = st.text_input("URL")

if url:
    orgs = set()
    results = set()
    req = requests.get(url, timeout=50)
    content = req.text
    items = content.splitlines()

    for item in items:
        if item.startswith("vmess://"):
            ip = vmess(item)
        elif item.startswith("trojan://"):
            ip = trojanvless(item)
        elif item.startswith("ss://"):
            ip = ss(item)
        else:
            continue
        info = get_info(ip)
        org = info["org"]
        country = info["country"]
        if org not in orgs:
            orgs.add(org)
        results.add({"link": item, "org": org, "country": country})

    cont = st.container()
    cont.write("Đã xong! Hãy mở thanh bên để kiểm tra.")

    with st.sidebar:
        for org in orgs:
            if st.button(org):
                for result in results:
                    if result["org"] == org:
                        cont.write(result["country"])
                        cont.code(result["link"])
