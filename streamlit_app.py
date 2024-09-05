import streamlit as st
from urllib.parse import urlparse, unquote
import json
import base64
import requests
import socket
import re

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

@st.cache_data(ttl=3600)
def get_info(ip):
    try:
        res_info = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
        return res_info
    except:
        return {"org": "Unknown", "country": "Unknown"}

def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False

def process_input(input_data):
    if input_data.startswith("http://") or input_data.startswith("https://"):
        try:
            req = requests.get(input_data, timeout=50)
            content = req.text
            return process_content(content)
        except:
            st.error("Failed to fetch the URL. Please check the URL and try again.")
            return []
    else:
        return process_content(input_data)

def process_content(content):
    if re.search(r'(vmess|trojan|vless|ss)://', content):
        return extract_links(content)
    elif is_base64(content):
        try:
            decoded = base64.b64decode(content).decode('utf-8')
            return extract_links(decoded)
        except:
            st.warning("Failed to decode base64 content.")
            return []
    else:
        st.warning("No valid links or base64 content found.")
        return []

def extract_links(text):
    links = re.findall(r'(vmess|trojan|vless|ss)://\S+', text)
    return links

st.title("Link Processor and Search")

url = st.text_input("Enter URL, base64 encoded data, or raw links")

if url:
    items = process_input(url)
    orgs = set()
    countries = set()
    results = []

    for item in items:
        addr = None
        if item.startswith("vmess://"):
            addr = vmess(item)
        elif item.startswith("trojan://") or item.startswith("vless://"):
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

    if results:
        st.write(f"Processed {len(results)} valid links")

        # Search functionality
        st.sidebar.header("Search and Display Options")
        search_org = st.sidebar.selectbox("Select Organization", ["All"] + sorted(list(orgs)))
        search_country = st.sidebar.selectbox("Select Country", ["All"] + sorted(list(countries)))
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
            st.text_area("Raw Links", raw_links, height=300)
            encoded_links = base64.b64encode(raw_links.encode()).decode()
            st.code(encoded_links, language="text")

        # Add download buttons
        st.sidebar.download_button(
            label="Download Raw Links",
            data=raw_links,
            file_name="raw_links.txt",
            mime="text/plain"
        )
        st.sidebar.download_button(
            label="Download Encoded Links",
            data=encoded_links,
            file_name="encoded_links.txt",
            mime="text/plain"
        )
    else:
        st.warning("No valid links found. Please check your input and try again.")
else:
    st.write("Please enter a URL, base64 encoded data, or raw links to process.")
