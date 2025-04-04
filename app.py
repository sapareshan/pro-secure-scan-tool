from flask import Flask, request, jsonify , render_template, make_response
from flask_cors import CORS
import subprocess
import shutil  #  Import shutil to check if Nmap exists
import re  # Import regex module for filtering open ports
import requests  # ✅ Import requests to fetch headers
from data_base import init_db, get_db_session , CompanyInfo, Vulnerabilities, runExtraQueries
import os
import json 
import subprocess
from urllib.parse import urljoin
from urllib.parse import urlparse
import multiprocessing
import time
import os
from datetime import datetime
import socket
import requests
import random
from email_base import sendOtp


'''
from sqlalchemy import create_engine;
from typing import List
from typing import Optional
# from sqlalchemy import ForeignKey
# from sqlalchemy import String
# from sqlalchemy.orm import DeclarativeBase
# from sqlalchemy.orm import Mapped
# from sqlalchemy.orm import mapped_column
# from sqlalchemy.orm import relationship
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON




Base = declarative_base()



# Define the CompanyInfo model
class CompanyInfo(Base):
    __tablename__ = 'company_info'

    id = Column(Integer, primary_key=True, autoincrement=True)
    temp_id = Column(Integer, unique=True, nullable=False)
    company_name = Column(String(255), nullable=True,default="Unknown")
    email = Column(String(255), nullable=True, unique=False)
    url = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<CompanyInfo(id={self.id}, company_name={self.company_name}, email={self.email})>"

# Define the Vulnerability model
class Vulnerabilities(Base):
    __tablename__ = 'vulnerabilities'

    company_id = Column(Integer, ForeignKey('company_info.id'), primary_key=True)  # Foreign Key & Primary Key
    missing_headers = Column(JSON, nullable=True)  # JSON type for missing headers
    ports = Column(JSON, nullable=True)  # Port field as a string, or Integer if you prefer
    version_vulnerabilities = Column(JSON, nullable=True)  # ✅ Store version-based vulnerabilities


    # Define the relationship to CompanyInfo
    company = relationship("CompanyInfo", backref="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerabilities(company_id={self.company_id}, ports={self.ports}, missing_headers={self.missing_headers})>"
  
engine = create_engine('mysql+pymysql://root:Mega442001#@localhost/pro_secure');

# Session factory, bound to the engine
Session = sessionmaker(bind=engine)

# Create a new session
session = Session()


try: 
    with engine.connect() as connection:
        print('connected')
except Exception as e:
        print(e);

# Session = sessionmaker(bind=engine);
# session = Session();

session.commit()

Base.metadata.create_all(engine)
'''





app = Flask(__name__, template_folder="templates")
CORS(app, resources={r"/*": {"origins": "*"}})  # Allows frontend (PHP) to call API from another domain

# ✅ Initialize Database (Create Tables)
init_db()
runExtraQueries()

# ✅ Get a new session for database operations
session = get_db_session()


@app.route("/")
def home():
    return render_template("index.html")  # Serve the HTML page

def is_domain_live(domain):
    """
    ✅ Checks if a domain is live using curl.
    ✅ Returns True if reachable, else False.
    """
    try:
        result = subprocess.run(
            ["curl", "-Is", "--connect-timeout", "5", domain],
            capture_output=True, text=True, timeout=20
        )
        if "HTTP/" in result.stdout:  # ✅ Found valid HTTP response
            return True
    except subprocess.TimeoutExpired:
        pass  # Ignore timeout errors

    return False  # ❌ Not live

# ✅ Directory for storing JSON results
SCAN_RESULTS_DIR = "scan_results"

# ✅ Ensure directory exists
if not os.path.exists(SCAN_RESULTS_DIR):
    os.makedirs(SCAN_RESULTS_DIR)

def save_scan_result(temp_id, scan_data):
    """ ✅ Save scan data to a JSON file (creates if not exists) using temp_id """
    # ✅ Ensure the directory exists
    os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)

    file_path = os.path.join(SCAN_RESULTS_DIR, f"{temp_id}.json")

    try:
        # ✅ If the file exists, load existing data
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                existing_data = json.load(file)
        else:
            existing_data = {}  # ✅ Create new JSON structure

        # ✅ Update with new scan data
        existing_data.update(scan_data)  

        # ✅ Write updated JSON file
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(existing_data, file, indent=4)

        # ✅ Print JSON response correctly
        print("✅ Scan results (JSON format):")
        print(json.dumps(existing_data, indent=4))  # Correct print format

    except json.JSONDecodeError:
        print(f"❌ Error reading JSON file (possibly corrupted): {file_path}")
    except Exception as e:
        print(f"❌ Error saving scan result for temp_id {temp_id}: {e}")



# @app.route("/scan-results/<int:company_id>", methods=["GET"])
# def get_scan_results(company_id):
#     """ ✅ Fetch scan results using temp_id """
#     file_path = os.path.join(SCAN_RESULTS_DIR, f"{company_id}.json")

#     # ✅ Check if file exists before serving
#     if not os.path.exists(file_path):
#         return jsonify({"error": "Scan results not found"}), 404

#     try:
#         # ✅ Serve JSON file efficiently
#         return send_file(file_path, mimetype="application/json")
    
#     except Exception as e:
#         print(f"❌ Error serving scan results for company_id {company_id}: {e}")
#         return jsonify({"error": "Internal Server Error"}), 500      








# Initialize Database
# def init_db():
#     conn = sqlite3.connect("scan_results.db")
#     cursor = conn.cursor()
#     cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
#                         id INTEGER PRIMARY KEY AUTOINCREMENT,
#                         domain TEXT,
#                         open_ports TEXT,
#                         timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
#     conn.commit()
#     conn.close()





def is_nmap_installed():
    return shutil.which("nmap") is not None  #  Check if Nmap exists

# Function to run Nmap scan
def run_nmap_scan(domain):
    if not is_nmap_installed():  # Check before running
        return "Nmap is not installed or not found in PATH."


    try:
        # Running Nmap to scan top 200 vulnerability ports within 5 seconds
        result = subprocess.run(
            #["nmap", "-T4", "--top-ports", "200", "--host-timeout", "60s", domain],  
            #["nmap", "-T4", "--top-ports", "200", "-Pn", "--script", "vuln", domain],
            ["nmap", "-T5", "-p-", "--min-rate=1000", "-Pn", "--open", "--script", "vuln", domain],
            capture_output=True, text=True
        )
        # Extract only open ports using regex
        open_ports = re.findall(r"(\d+)/tcp\s+open", result.stdout)

        if not open_ports:
            return "No open ports found!"
        

        return ", ".join(open_ports)  # Return only open ports as a string
    except subprocess.TimeoutExpired:
        return "Scan timed out!"    

# ✅ Define the top 20 security headers
TOP_20_HEADERS = [
    "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options",
    "Referrer-Policy", "Content-Security-Policy", "Permissions-Policy", "Cache-Control",
    "Pragma", "Expires", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers", "Feature-Policy", "Expect-CT", "Public-Key-Pins",
    "NEL", "Server-Timing", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy"
]    


def check_missing_headers(domain):
    try:
        url = f"http://{domain}"  # ✅ Try HTTP first
        response = requests.get(url, timeout=5)

        # ✅ Convert response headers to lowercase for case-insensitive matching
        response_headers = {header.lower() for header in response.headers.keys()}

        # ✅ Check which security headers are missing
        missing_headers = [header for header in TOP_20_HEADERS if header.lower() not in response_headers]

        return missing_headers  # ✅ Return only the missing ones

    except requests.RequestException:
        return []  # ✅ Handle unreachable domains
    
def get_http_headers(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        return dict(response.headers)  # ✅ Convert headers to a dictionary
    except requests.RequestException:
        return {}   


    
def detect_technology(domain):
    try:
        url = f"http://{domain}"  # Try HTTP first
        response = requests.get(url, timeout=5)
        
        headers = response.headers

        # Extract Server & X-Powered-By
        server = headers.get("Server", "Unknown").lower()
        x_powered_by = headers.get("X-Powered-By", "").lower()

        # Identify Programming Language
        if "PHP" in x_powered_by or "PHP" in server:
            language = "PHP"
        elif "ASP.NET" in x_powered_by or "ASP.NET" in server:
            language = "ASP.NET"
        elif "Node.js" in x_powered_by:
            language = "Node.js"
        elif "Python" in x_powered_by:
            language = "Python"
        elif "Java" in x_powered_by:
            language = "Java"
        else:
            language = "Unknown"

        # Identify CMS based on response body
        cms = "Unknown"
        if "wp-content" in response.text:
            cms = "WordPress"
        elif "Joomla" in response.text:
            cms = "Joomla"
        elif "Drupal" in response.text:
            cms = "Drupal"

        return {
            "server": server,
            "language": language,
            "cms": cms
        }

    except requests.RequestException:
        return {"server": "Error", "language": "Error", "cms": "Error"}     
    

def perform_fuzzing(domain, server, language, cms):

    # ✅ Convert to lowercase
    server = server.lower()
    language = language.lower()
    cms = cms.lower()

# Use relative paths for wordlists
    FUZZ_DIR = "fuzz_finder"
    WORDLISTS = {
        "php": os.path.join(FUZZ_DIR, "php_wordlist.txt"),
        "asp.net": os.path.join(FUZZ_DIR, "asp_wordlist.txt"),
        "node.js": os.path.join(FUZZ_DIR, "node_wordlist.txt"),
        "python": os.path.join(FUZZ_DIR, "python_wordlist.txt"),
        "java": os.path.join(FUZZ_DIR, "java_wordlist.txt"),
        "wordpress": os.path.join(FUZZ_DIR, "wordpress_wordlist.txt"),
        "joomla": os.path.join(FUZZ_DIR, "joomla_wordlist.txt"),
        "drupal": os.path.join(FUZZ_DIR, "drupal_wordlist.txt"),
        "apache": os.path.join(FUZZ_DIR, "apache_wordlist.txt"),
        "nginx": os.path.join(FUZZ_DIR, "nginx_wordlist.txt"),
    }    

# ✅ Choose the most relevant wordlist
    wordlist = None
    if language in WORDLISTS:
        wordlist = WORDLISTS[language]
    if cms in WORDLISTS:
         wordlist = WORDLISTS[cms]
    if server in WORDLISTS:
      wordlist = WORDLISTS[server]

    print(wordlist)
    # 🚫 If no wordlist is found or missing, skip the scan
    if not wordlist or not os.path.isfile(wordlist):
        print(f"⚠️ Wordlist not found for {language}/{cms}/{server}. Skipping scan.")
        return []
    
    print(f"✅ Using wordlist: {wordlist}")

    # 🔎 Find misconfigurations
    exposed_files = []
    try:
        with open(wordlist, "r") as f:
            endpoints = [line.strip() for line in f]

        for endpoint in endpoints:
            url = f"http://{domain}/{endpoint}"  # Try HTTP first
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:  # ✅ Found an exposed file!
                    print(f"🟢 Found: {url}")
                    exposed_files.append(url)
            except requests.RequestException:
                pass  # Ignore unreachable URLs

    except FileNotFoundError:
        pass  # No errors if the file is missing
   

    return exposed_files

def run_xsstrike(url):
    """Run XSStrike against a given URL to detect XSS vulnerabilities with details."""
    try:
        command = ["python3", "XSStrike/xsstrike.py", "--url", url, "--crawl", "--blind"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        output = result.stdout
        xss_vulnerability = []

        for line in output.split("\n"):
            if "Vulnerable" in line:  # Adjust based on actual XSStrike output
                parts = line.split(":")
                if len(parts) >= 3:
                    vuln_url = parts[0].strip()
                    vuln_param = parts[1].strip()
                    payload = parts[2].strip()
                    xss_vulnerability.append({
                        "url": vuln_url,
                        "parameter": vuln_param,
                        "payload": payload,
                        "type": "Reflected XSS"  # Modify based on detection logic
                    })
        
        return xss_vulnerability if xss_vulnerability else None
    except Exception as e:
        return str(e)

# def scan_open_redirection(domain):
#     """Scans for Open Redirection vulnerabilities using a wordlist file."""
#     PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "open_redirection", "open_redirect_wordlist.txt")
#     vulnerable_urls = []

#     try:
#         with open(PAYLOAD_FILE, "r", encoding="utf-8") as file:
#             payloads = [line.strip() for line in file if line.strip()]
#     except FileNotFoundError:
#         print(f"⚠️ Payload file not found: {PAYLOAD_FILE}")
#         return []
    

#      # ✅ Ensure the domain is parsed correctly
#     parsed_domain = urlparse(domain).netloc
#     # pay="go-koala.com"
#     # test="http://google.com:80#@www.whitelisteddomain.tld/"

#     for payload in payloads:
#         # ✅ Construct test URL correctly
#         if payload.startswith(("http://", "https://", "//")):
#             test_url = payload  # Use absolute or scheme-relative URL as-is
#         elif payload.startswith("/"):
#             test_url = domain.rstrip("/") + payload  # Ensure no double slashes
#         else:
#             test_url = domain.rstrip("/") + "/" + payload  # Add single slash
#         print(test_url)
#         # print(test_url = urljoin(pay,test))
#         try:
#             response = requests.get(test_url, allow_redirects=True, timeout=5)
#             final_url = response.url


#             if response.history and urlparse(final_url).netloc != parsed_domain: # ✅ Check if redirection happened
#                 vulnerable_urls.append({"payload": test_url, "redirected_to": final_url})
#                 print(f"[!] Open Redirection Found: {test_url} → {final_url}")
#         except requests.RequestException:
#             continue  # Ignore request errors

def scan_open_redirection(domain):
    """
    Scans a given domain for Open Redirection vulnerabilities using a wordlist.
    
    ✅ Loads payloads from `open_redirection/open_redirect_wordlist.txt`
    ✅ Checks if the site redirects to an external domain
    ✅ Avoids false positives from same-site redirects
    ✅ Ensures at least one redirect occurs
    """
    # Load the wordlist
    PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "open_redirection", "open_redirect_wordlist.txt")
    try:
        with open(PAYLOAD_FILE, "r", encoding="utf-8") as file:
            payloads = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"⚠️ Payload file not found: {PAYLOAD_FILE}")
        return []

    vulnerable_urls = []
    original_domain = urlparse(domain).netloc.lower()

    for payload in payloads:
        # Directly use the payload as the test URL
        test_url = urljoin(domain, payload)

        try:
            response = requests.get(test_url, allow_redirects=True, timeout=5)
            final_url = response.url
            final_domain = urlparse(final_url).netloc.lower()

            # ✅ Strict Open Redirect Detection:
            if (
                response.history and  # Ensure redirection occurred
                final_domain and final_domain != original_domain and  # Ensure external redirection
                not final_domain.endswith(original_domain) and  # Prevent subdomain false positives
                not final_domain.startswith("www." + original_domain)  # Ignore "www" subdomains
                
            ):
                print(test_url)    
                
                vulnerable_urls.append({"payload": test_url, "redirected_to": final_url})
                print(f"[🔥] Open Redirect Found: {test_url} → {final_url}")

        except requests.RequestException:
            continue  # Ignore errors and timeouts

    return vulnerable_urls        

# #def detect_os_command_injection(domain):
OS_COMMAND_INJECTION_DIR = "OS_COMMAND_INJECTION_DIR"

def load_wordlist(file_name):
    """ Load wordlist from the OS_COMMAND_INJECTION_DIR folder """
    file_path = os.path.join(OS_COMMAND_INJECTION_DIR, file_name)
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return [line.strip() for line in file.readlines()]
    return []


def enumerate_directories(domain):
    """ ✅ Enumerate directories using wordlist and store in DB """
    detected_directories = []
    directory_wordlist = load_wordlist("directories.txt")  # ✅ Load directories list

    print(f"🔍 Enumerating directories for {domain}...")

    for directory in directory_wordlist:
        test_url = f"http://{domain}/{directory}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code in [200, 301, 302]:  # ✅ Valid directory found
                detected_directories.append({"directory": directory, "url": test_url})
                print(f"✅ Found: {test_url}")
        except requests.RequestException:
            pass  # Ignore errors


def check_clickjacking(domain):
    """
    Checks if the given domain is vulnerable to Clickjacking.
    Returns a dictionary with the scan results.
    """
    try:
        # Send a GET request to fetch the headers
        url = f"https://{domain}" if not domain.startswith("http") else domain
        response = requests.get(url, timeout=10)

        # Extract security headers
        x_frame_options = response.headers.get("X-Frame-Options", "").lower()
        content_security_policy = response.headers.get("Content-Security-Policy", "").lower()

        # Check if the website is vulnerable
        vulnerable = False
        vulnerability_reason = ""

        if "deny" in x_frame_options or "sameorigin" in x_frame_options:
            vulnerability_reason = "Protected (X-Frame-Options is set correctly)"
        elif "frame-ancestors" in content_security_policy:
            vulnerability_reason = "Protected (CSP frame-ancestors is set)"
        else:
            vulnerability_reason = "Vulnerable! No X-Frame-Options or CSP protection found."
            vulnerable = True

        # Return the scan result
        return {
            "domain": domain,
            "x_frame_options": x_frame_options if x_frame_options else "Not Set",
            "content_security_policy": content_security_policy if content_security_policy else "Not Set",
            "vulnerable": vulnerable,
            "message": vulnerability_reason
        }

    except requests.RequestException as e:
        return {"error": f"Failed to check Clickjacking for {domain}: {str(e)}"}


def perform_full_scan(domain, entry_id, company_id):
    """Runs all security scans one by one and stores each result in the database."""
    #session = get_db_session()  # Get DB session
 
    # company_id = company_id.id

    print('hi_______->')
    print(company_id)

     # 🔍 Step 1: Check if the domain is live
   

    try:

        scan_results = {}
        scan_result = run_nmap_scan(domain)
        open_ports = scan_result.split(", ") if scan_result and scan_result != "No open ports found!" else []
        open_ports.append("890")
        vulnerable_ports = [port for port in open_ports if port not in ["80", "443"]]

        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {"ports": vulnerable_ports}
        )
        
        # session.add(Vulnerabilities(company_id=company_id, ports=vulnerable_ports))
        session.commit()
        save_scan_result(entry_id, {"open_ports": open_ports})
        save_scan_result(entry_id, {"vulnerable_ports": vulnerable_ports})
        print(f"✅ Nmap Scan completed for {domain}")


         # ✅ Check Missing Headers
        missing_headers = check_missing_headers(domain)
        #http_headers = get_http_headers(domain)
        
        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {  "missing_headers": missing_headers}
        )
        session.commit()
        save_scan_result(entry_id, {"missing_headers": missing_headers})
        print(f"✅ Missing Header Analysis completed for {domain}")



        # ✅ Detect Server, Language, CMS
        tech_info = detect_technology(domain)
        tech_data = json.loads(tech_info) if isinstance(tech_info, str) else tech_info
        server = tech_data.get("server", "Unknown")
        language = tech_data.get("language", "Unknown")
        cms = tech_data.get("cms", "Unknown")

        exposed_files = []
        if server != "Unknown" or language != "Unknown" or cms != "Unknown":
            exposed_files = perform_fuzzing(domain, server, language, cms)
        
        updated_tech_info = [
            {"techinfo": f"{language}, {server}"},
            {"techinfoVulnerability": exposed_files} if exposed_files else {"techinfoVulnerability": {}}
        ]

        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {"technology_info": updated_tech_info}
        )
        session.commit()
        save_scan_result(entry_id, {"updated_tech_info": updated_tech_info})
        print(f"✅ Technology Detection completed for {domain}")


        # ✅ Run XSStrike for XSS scanning
        xss_results = run_xsstrike(domain)
        xss_vuln_data = xss_results if xss_results else []

        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {"xss_vulnerabilities": xss_vuln_data}
        )
        session.commit()
        save_scan_result(entry_id, {"xss_vuln_data": xss_vuln_data})
        print(f"✅ XSS Scan completed for {domain}")



        # ✅ Open Redirection Scan
        open_redirect_vulnerabilities = scan_open_redirection(domain)

        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {"open_redirection_vulnerabilities": open_redirect_vulnerabilities}
        )
        session.commit()
        save_scan_result(entry_id, {"open_redirect_vulnerabilities": open_redirect_vulnerabilities})
        print(f"✅ Open Redirection Scan completed for {domain}")

                 # ✅ Detect OS Command Injection
        # os_command_vulns = detect_os_command_injection(domain)
        # session.query(Vulnerabilities).filter_by(company_id=entry_id).update({"os_command_injection_vulnerabilities": os_command_vulns})
        # session.commit()
        # save_scan_result(entry_id, {"os_command_injection_vulnerabilities": os_command_vulns})
        # print(f"✅ OS Command Injection Scan completed for {domain}")

        

        directory_enumration_vuln = enumerate_directories(domain)

        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {"Directory_enumration_vulnerabilities": directory_enumration_vuln}
        )
        session.commit()
        save_scan_result(entry_id, {"Directory_enumration_vulnerabilities": directory_enumration_vuln})
        print(f"✅ Open Redirection Scan completed for {domain}")

                # ✅ Run Clickjacking Scan
        clickjacking_result = check_clickjacking(domain)

        # ✅ Save Clickjacking vulnerability in DB
        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {"clickjacking_vulnerability": clickjacking_result}
        )
        session.commit()

        # ✅ Save Clickjacking scan result to JSON file
        save_scan_result(entry_id, {"clickjacking_vulnerability": clickjacking_result})

        print(f"✅ Clickjacking Scan completed for {domain}")


        print(f"✅ All scans completed for {domain}")
        save_scan_result(entry_id, {"status": "complete"})





            # ✅ Mark scan as complete
        # scan_results["scan_complete"] = True 

        # # Save results to JSON
        # save_scan_result(company_id , scan_results)




    except Exception as e:
        print(f"❌ Error during scan: {e}")
        session.rollback()
    
    finally:
        session.close()

def count_vulnerabilities(scan_data):
    """Count total vulnerabilities found across all checks"""
    total_vulnerabilities = 0

    # Count each type of vulnerability
    if scan_data.get("missing_headers"):
        total_vulnerabilities += len(scan_data["missing_headers"])

    if scan_data.get("vulnerable_ports"):
        total_vulnerabilities += len(scan_data["vulnerable_ports"])

    if scan_data.get("xss_vuln_data"):
        total_vulnerabilities += len(scan_data["xss_vuln_data"])

    if scan_data.get("open_redirect_vulnerabilities"):
        total_vulnerabilities += len(scan_data["open_redirect_vulnerabilities"])

    if scan_data.get("Directory_enumration_vulnerabilities"):
        total_vulnerabilities += len(scan_data["Directory_enumration_vulnerabilities"])

    # Count exposed files if they exist in tech info
    if scan_data.get("updated_tech_info") and len(scan_data["updated_tech_info"]) > 1:
        tech_vuln = scan_data["updated_tech_info"][1].get("techinfoVulnerability")
        if tech_vuln:
            total_vulnerabilities += len(tech_vuln)

    return total_vulnerabilities




@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        if not data or "domain" not in data:
            return jsonify({"error": "No domain provided"}), 400
        
        domain = data["domain"]
        
        print("Received domain:", domain)
        
        if not is_domain_live(domain):
            print(f"⚠️ Skipping scans: {domain} is not live!")

             # Store the result immediately in DB
            # session.query(Vulnerabilities).filter_by(company_id=new_entry.id).update(
            #     {"scan_status": "Domain is not live"}
            # )
            # session.commit()
            return jsonify({"message": "Not Live","temp_id": None, "domain": domain})
    

        print(f"🚀 {domain} is live! Proceeding with scans...")
        # Get the latest temp_id and increment it (ensure uniqueness)
        now = datetime.now().timestamp();
        now = str(now);
        rand_temp_id_index = now.rfind('.');
        rand_temp_id = now[(rand_temp_id_index + 1):];

        max_temp_id = session.query(CompanyInfo.temp_id).filter(CompanyInfo.temp_id == rand_temp_id).first()

        new_temp_id = rand_temp_id;
        #Auto-increment



         # ✅ Generate a unique placeholder email
        #unique_email = f"unknown_{new_temp_id}@example.com"
        

        # Insert new company entry with unique temp_id
        new_entry = CompanyInfo(temp_id=new_temp_id, company_name=None,email=None, url=domain)
        session.add(new_entry)
        session.commit()  # ✅ Commit first to generate `id`

# ✅ Fetch the committed entry to ensure `id` is available
        session.refresh(new_entry)  # ✅ Guarantees new_entry.id exists in DB

        #session = get_db_session()

        # ✅ Verify company_id exists in DB before inserting
        company_exists = session.query(CompanyInfo).filter_by(id=new_entry.id).first()
        if not company_exists:
            raise Exception(f"Company ID {new_entry.id} not found in the database!")
        
        company_id = session.query(CompanyInfo.id).filter(CompanyInfo.id == new_temp_id).first();
        session.commit()

        http_headers = get_http_headers(domain)
        
      

        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            { "info_http_headers": http_headers}
        )
        session.commit()
        save_scan_result(new_temp_id, {"url": domain})
        save_scan_result(new_temp_id, {"http_headers": http_headers})
        print(f"✅ HTTP Header Analysis completed for {domain}")

        # ✅ Start background scan
        process = multiprocessing.Process(target=perform_full_scan, args=(domain, new_temp_id, company_id))
        process.start()



        #session.commit()  # Commit changes to store entry

        # Run Nmap scan
        ##scan_result = run_nmap_scan(domain)
        # scan_result = run_nmap_scan(domain)

        # # ✅ Filter out non-vulnerable ports (80, 443)
        # open_ports = scan_result.split(", ") if scan_result and scan_result != "No open ports found!" else []
        # open_ports.append("890")
        # vulnerable_ports = [port for port in open_ports if port not in ["80", "443"]]

        # ✅ Check missing headers
        # missing_headers = check_missing_headers(domain)
        # http_headers = get_http_headers(domain)
        #  # ✅ Detect Server, Language, and CMS
        # tech_info = detect_technology(domain)




        #  # ✅ Perform fuzzing if tech is detected
        # tech_data = json.loads(tech_info) if tech_info and isinstance(tech_info, str) else tech_info
        # server = tech_data.get("server", "Unknown")
        # language = tech_data.get("language", "Unknown")
        # cms = tech_data.get("cms", "Unknown")


        # exposed_files = []
        # if server == "Unknown" and language == "Unknown" and cms == "Unknown":
        #     print(f"⚠️ No known technology found for {domain}. Skipping misconfiguration scan.")
        #     exposed_files = []  # No scanning
        # else:    
            
        #     exposed_files = perform_fuzzing(domain, server, language, cms)


        #         # ✅ Format tech_info with vulnerabilities
        # updated_tech_info = [

        #     {"techinfo": f"{language}, {server}"},
        #     {"techinfoVulnerability": exposed_files} if exposed_files else {}
        # ]    

       
        
        #  # ✅ Run XSStrike for XSS scanning
        # xss_results = run_xsstrike(domain)

        # # ✅ Store XSS vulnerabilities with details
        # xss_vuln_data = xss_results if xss_results else []

        # # ✅ Open Redirection Scan
        # open_redirect_vulnerabilities = scan_open_redirection(domain)


       

        # # ✅ Store vulnerabilities in the database (INSIDE `scan()`)
        # vulnerability_entry = Vulnerabilities(
        #     company_id=new_entry.id, 
        #     ports=vulnerable_ports, # Link to company
        #     missing_headers=missing_headers , # ✅ Store missing headers
        #     info_http_headers=http_headers,
        #     technology_info=updated_tech_info,
        #     xss_vulnerabilities=xss_vuln_data ,
        #     open_redirection_vulnerabilities=open_redirect_vulnerabilities,
        # )
        # session.add(vulnerability_entry)
        # session.commit() 
        


        return jsonify({"message": "Scan started in the background","temp_id": new_temp_id, "domain": domain})

    except Exception as e:
        print(f"Error: {e}")  # Print error in Flask console
        session.rollback()  # Rollback changes if any error occurs
        return jsonify({"error": "Internal Server Error"}), 500  # Return JSON instead of HTML

'''
@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        if not data or "domain" not in data:
            return jsonify({"error": "No domain provided"}), 400
        
        domain = data["domain"]
        
        print("Received domain:", domain)
        
        scan_result = run_nmap_scan(domain)

        return jsonify({"domain": domain, "scan_result": scan_result})

    except Exception as e:
        print(f"Error: {e}")  #  Print error in Flask console
        return jsonify({"error": "Internal Server Error"}), 500  #  Return JSON instead of HTML
'''


@app.route("/scan/results/<temp_id>", methods=["GET"])
def get_scan_result(temp_id):
    """
    Route to fetch and return the scan result JSON data for a given `temp_id` (or company_id)
    """
    # Ensure SCAN_RESULTS_DIR is defined and accessible
    if not os.path.exists(SCAN_RESULTS_DIR):
        return jsonify({"error": "Scan results directory not found"}), 500

    # Generate the path to the JSON file for this scan
    file_path = os.path.join(SCAN_RESULTS_DIR, f"{temp_id}.json")
    
    if os.path.exists(file_path):
        # Read the JSON file
        with open(file_path, 'r') as file:
            scan_data = json.load(file)

            # Count total vulnerabilities
        total_vulnerabilities = count_vulnerabilities(scan_data)
        
        # Count total checks performed
        total_checks = 0
        check_types = ["http_headers", "open_ports", "vulnerable_ports", "missing_headers", 
                       "updated_tech_info", "xss_vuln_data", "open_redirect_vulnerabilities",
                       "Directory_enumration_vulnerabilities"]
        
        for check in check_types:
            if check in scan_data:
                total_checks += 1
        
        # Add counts to response
        scan_data["total_checks"] = total_checks
        scan_data["total_vulnerabilities"] = total_vulnerabilities
        scan_data["secure_count"] = total_checks - (1 if total_vulnerabilities > 0 else 0)
        scan_data["vulnerable_count"] = 1 if total_vulnerabilities > 0 else 0
        
        # Add status complete if not present
        if "status" not in scan_data:
            # Check if all scans have been completed
            if all(key in scan_data for key in ["http_headers", "open_ports", "vulnerable_ports", "missing_headers", 
                       "updated_tech_info", "xss_vuln_data", "open_redirect_vulnerabilities",
                       "Directory_enumration_vulnerabilities"]):
                scan_data["status"] = "complete"
        
        # Return the scan data as a JSON response
        return jsonify(scan_data)
    else:
        # If the file doesn't exist, return an error message
        return jsonify({"error": "Scan result not found for the given temp_id"}), 404

@app.route('/scan/company/<company_id>', methods=['POST', 'OPTIONS'])
def scan_company(company_id):
    if request.method == 'OPTIONS':
        return '', 200
            
    return jsonify({"status": "success", "message": "Data received"})

@app.route('/scan/company/<company_id>/verify-otp', methods=['POST', 'OPTIONS'])
def scan_verify_otp(company_id):
    if request.method == 'OPTIONS':
        return '', 200
            
    return jsonify({"status": "success", "message": "Data received"})

@app.route("/scan/generate-otp/<int:temp_id>", methods=["POST"])
def generateOtp(temp_id):

    companyData = session.query(CompanyInfo).filter_by(temp_id=int(temp_id)).first()
    if not companyData:
        data = jsonify({'msg': 'There is not enough data...', "isGenerated": False})
        res = make_response(data) 
        res.delete_cookie('retries_attempted', domain=request.host)
        res.status_code = 400
        return res

    formData = request.get_json()

    if not formData or not 'email' in formData or not 'companyName' in formData:
        res = make_response(jsonify({'isGenerated': False, 'msg': "Some data's are not presented", 'formData': formData}))
        res.status_code = 400
        return res

    company_name = str(formData['companyName'])
    email = str(formData['email'])

    otp = generate_otp()
    session.query(CompanyInfo).filter(CompanyInfo.temp_id == int(temp_id)).update(
        {"otp": int(otp), "company_name": company_name, "email": email}
    )
    session.commit()

    body = f"Your OTP is {otp}"
    sendOtp(receiver_email=email, body=body)

    return jsonify({"msg": "Otp generated", "isGenerated": True, "otp": otp})



@app.route("/scan/verify-otp/<int:temp_id>", methods=["POST"])
def verifyOtp(temp_id):

    companyData = session.query(CompanyInfo).filter_by(temp_id=int(temp_id)).first()
    if not companyData:
        data = jsonify({'msg': 'There is not enough data...', "isGenerated": False})
        res = make_response(data) 
        res.delete_cookie('retries_attempted', domain=request.host)
        res.status_code = 400
        return res

    formData = request.get_json()
    cookies = request.cookies
    otp = retries_attempted = None

    if not formData or not 'otp' in formData:
        res = make_response(jsonify({'isVerified': False, 'isMaxRetired': False}))
        res.status_code = 400
        return res
    else:
        otp = int(formData['otp'])
    
    if cookies and 'retries_attempted' in cookies:
        retries_attempted = cookies['retries_attempted']
    
    if not retries_attempted:
        retries_attempted = 1
    else:
        retries_attempted = int(retries_attempted) + 1

    if retries_attempted and int(retries_attempted) > 3:
        return jsonify({"msg": "max retries reached", "isMaxRetried": True, 'isVerified': False})
    
    
    company = session.query(CompanyInfo).filter(CompanyInfo.temp_id == int(temp_id)).first()

    isVerified = company.otp == otp

    retries_attempted = 3 if isVerified else retries_attempted
    isMaxVerified = True if isVerified else False

    data = jsonify({"msg": "Verified" if isVerified else "Not verified", "retries": retries_attempted, "isMaxRetried": isMaxVerified, "isVerified": isVerified})

    res = make_response(data)
    res.set_cookie(key='retries_attempted', value=str(retries_attempted), max_age=60*2)

    return res


def generate_otp():
    return random.randint(100000, 999999)


@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response
   


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)  