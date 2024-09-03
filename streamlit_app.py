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
    return requests.get(f"http://ipinfo.io/{ip}/json", timeout=5).json()


st.title("Link Processor and Search")

url = st.text_input("URL")

if url:
    orgs = set()
    countries = set()
    results = []
    if url.startswith("http://") or url.startswith("https://"):
        req = requests.get(url, timeout=50)
        content = req.text
        items = content.splitlines()
    else:
        items = url.split()

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
        orgs.add(org)
        countries.add(country)
        results.append({"link": item, "org": org, "country": country})

    st.write(f"Processed {len(results)} links")

    # Search functionality
    st.sidebar.header("Search")
    search_org = st.sidebar.selectbox("Select Organization", ["All"] + list(orgs))
    search_country = st.sidebar.selectbox("Select Country", ["All"] + list(countries))

    # Filter results
    filtered_results = results
    if search_org != "All":
        filtered_results = [r for r in filtered_results if r["org"] == search_org]
    if search_country != "All":
        filtered_results = [
            r for r in filtered_results if r["country"] == search_country
        ]

    # Display results
    st.header("Results")
    for result in filtered_results:
        st.write(f"Organization: {result['org']}")
        st.write(f"Country: {result['country']}")
        st.code(result["link"])
        st.markdown("---")

else:
    st.write("Please enter a URL to process.")
