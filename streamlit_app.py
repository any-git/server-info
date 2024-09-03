from urllib.parse import urlparse, unquote
import json
import base64
import streamlit as st
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import ipaddress


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


def get_info(ip):
    try:
        res_info = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()
        return res_info
    except:
        return {"org": "Unknown", "country": "Unknown"}


def check_proxy(ip, port, proxy_type):
    proxies = {
        "http": f"{proxy_type}://{ip}:{port}",
        "https": f"{proxy_type}://{ip}:{port}",
    }
    try:
        response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=5)
        return response.status_code == 200
    except:
        return False


def process_link(item, link_type):
    if link_type == "proxy":
        try:
            ip, port = item.split(":")
            port = port.split("#")[0]  # Remove any comments after the port
            proxy_type = st.session_state.proxy_type
            is_valid_ip = ipaddress.ip_address(
                ip
            )  # This will raise an exception if IP is invalid
            info = get_info(ip)
            is_available = check_proxy(ip, port, proxy_type)
            return {
                "link": item,
                "org": info.get("org", "Unknown"),
                "country": info.get("country", "Unknown"),
                "ip": ip,
                "port": port,
                "proxy_type": proxy_type,
                "is_available": is_available,
            }
        except:
            return None
    else:
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
            return {
                "link": item,
                "org": info.get("org", "Unknown"),
                "country": info.get("country", "Unknown"),
                "ip": ip,
            }
    return None


st.title("Link Processor and Proxy Checker")

link_type = st.radio("Select link type", ["VPN/SS", "Proxy"])

if link_type == "Proxy":
    st.session_state.proxy_type = st.selectbox(
        "Select proxy type", ["http", "https", "socks5"]
    )

url = st.text_area("Enter URLs or proxy addresses (one per line)")

if url:
    start_time = time.time()
    orgs = set()
    countries = set()
    results = []

    items = url.split("\n")

    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_link = {
            executor.submit(process_link, item.strip(), link_type): item
            for item in items
            if item.strip()
        }
        for future in as_completed(future_to_link):
            result = future.result()
            if result:
                results.append(result)
                orgs.add(result["org"])
                countries.add(result["country"])

    end_time = time.time()
    st.write(
        f"Processed {len(results)} valid links in {end_time - start_time:.2f} seconds"
    )

    if link_type == "VPN/SS":
        # Search functionality
        st.sidebar.header("Search and Display Options")
        search_org = st.sidebar.selectbox("Select Organization", ["All"] + list(orgs))
        search_country = st.sidebar.selectbox(
            "Select Country", ["All"] + list(countries)
        )
        display_type = st.sidebar.radio("Display Type", ["Detailed", "Raw"])

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
    else:  # Proxy results
        st.header("Proxy Results")
        for result in results:
            st.write(f"IP: {result['ip']}")
            st.write(f"Port: {result['port']}")
            st.write(f"Type: {result['proxy_type']}")
            st.write(f"Organization: {result['org']}")
            st.write(f"Country: {result['country']}")
            st.write(f"Available: {'Yes' if result['is_available'] else 'No'}")
            st.markdown("---")

else:
    st.write("Please enter URLs or proxy addresses to process.")
