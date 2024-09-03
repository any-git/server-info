from urllib.parse import urlparse, unquote
import json
import base64
import streamlit as st
import requests
import socket

def trojanvless(link):
    try:
        parsed = urlparse(link)
        netloc = parsed.netloc
        ipport = netloc.split("@")[1]
        return ipport.split(":")[0]
    except:
        return None

def vmess(link):
    try:
        inf = link.replace("vmess://", "")
        decoded = base64.b64decode(inf).decode("utf-8")
        data = json.loads(decoded)
        return data["add"]
    except:
        return None

def ss(link):
    try:
        parsed = urlparse(link)
        if parsed.netloc:
            parts = parsed.netloc.split("@")
            if len(parts) > 1:
                return parts[1].split(":")[0]
        
        inf = link.replace("ss://", "")
        inf = inf.split("#")[0]
        decoded = base64.b64decode(inf).decode()
        ipport = decoded.split("@")[1]
        return ipport.split(":")[0]
    except:
        return None

def get_ip(address):
    try:
        return socket.gethostbyname(address)
    except socket.gaierror:
        return address  # Return the original address if resolution fails

req_log = st.container()

def get_info(ip):
    try:
        res_info = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
        print(res_info)
        return res_info
    except:
        return {"org": "Unknown", "country": "Unknown"}

st.title("Link Processor and Search")

url = st.text_input("URL")

if url:
    orgs = set()
    countries = set()
    results = []
    if url.startswith("http://") or url.startswith("https://"):
        try:
            req = requests.get(url, timeout=50)
            content = req.text
            items = content.splitlines()
        except:
            st.error("Failed to fetch the URL. Please check the URL and try again.")
            items = []
    else:
        items = url.split()

    for item in items:
        addr = None
        if item.startswith("vmess://"):
            addr = vmess(item)
        elif item.startswith("trojan://"):
            addr = trojanvless(item)
        elif item.startswith("ss://"):
            addr = ss(item)

        if addr:
            ip = get_ip(addr)
            info = get_info(ip)
            org = info.get("org", "Unknown")
            country = info.get("country", "Unknown")
            orgs.add(org)
            countries.add(country)
            results.append({"link": item, "org": org, "country": country, "ip": ip})

    st.write(f"Processed {len(results)} valid links")

    # Search functionality
    st.sidebar.header("Search and Display Options")
    search_org = st.sidebar.selectbox("Select Organization", ["All"] + list(orgs))
    search_country = st.sidebar.selectbox("Select Country", ["All"] + list(countries))
    display_type = st.sidebar.radio("Display Type", ["Detailed", "Raw"])

    # Filter results
    filtered_results = results
    if search_org != "All":
        filtered_results = [r for r in filtered_results if r["org"] == search_org]
    if search_country != "All":
        filtered_results = [r for r in filtered_results if r["country"] == search_country]

    # Display results
    st.header("Results")
    if display_type == "Detailed":
        for result in filtered_results:
            st.write(f"Organization: {result['org']}")
            st.write(f"Country: {result['country']}")
            st.write(f"IP Address: {result['ip']}")
            st.code(result["link"])
            st.markdown("---")
    else:  # Raw display
        raw_links = "\n".join([r["link"] for r in filtered_results])
        encoded_links = base64.b64encode(raw_links.encode()).decode()
        st.code(encoded_links, language="text")

else:
    st.write("Please enter a URL to process.")
