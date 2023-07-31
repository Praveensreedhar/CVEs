import smtplib
import requests
import json
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime, timedelta, timezone
from dateutil import parser

def get_last_week_published_cve_details(limit=10):
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
    target_domains = ["solarwinds.com", "cisco.com", "juniper.net", "citrix.com"]
    
    # Calculate the date for one week ago from the current date and make it offset-aware
    one_week_ago = datetime.now(timezone.utc) - timedelta(weeks=1)
    
    cve_details_str = ""  # Initialize the CVE details string
    
    try:
        response = requests.get(base_url, stream=True)
        response.raise_for_status()
        
        # Read the content of the ZIP file and extract the CVE data
        with ZipFile(BytesIO(response.content)) as zip_file:
            with zip_file.open("nvdcve-1.1-recent.json") as json_file:
                data = json.load(json_file)
                cves = data.get("CVE_Items", [])

                found_cves = False  # Flag to check if any relevant CVEs were found

                for cve in cves[:limit]:
                    cve_id = cve.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
                    cve_description = cve.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
                    cve_published_date = cve.get("publishedDate", "")
                    cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    
                    # Parse the published date string to an offset-aware datetime object for comparison
                    published_date = parser.parse(cve_published_date).replace(tzinfo=timezone.utc)
                    
                    # Check if the CVE was published in the last week
                    if published_date >= one_week_ago:
                        # Extract reference URLs containing target domains
                        references = cve.get("cve", {}).get("references", {}).get("reference_data", [])
                        target_domain_references = [ref.get("url", "") for ref in references if any(domain in ref.get("url", "") for domain in target_domains)]

                        if target_domain_references:
                            found_cves = True  # Set the flag to True if any relevant CVEs are found
                            cve_details_str += f"CVE ID: {cve_id}\n"
                            cve_details_str += f"Description: {cve_description}\n"
                            cve_details_str += f"Published Date: {cve_published_date}\n"
                            cve_details_str += f"CVE URL: {cve_url}\n"
                            cve_details_str += "Reference URLs:\n"
                            for ref_url in target_domain_references:
                                cve_details_str += f"{ref_url}\n"
                            cve_details_str += "=" * 50 + "\n"

                if not found_cves:
                    cve_details_str = "No CVEs with references to 'solarwinds.com', 'cisco.com', 'juniper.net', or 'citrix.com' published in the last week."

    except requests.exceptions.RequestException as e:
        print("Error: Unable to retrieve latest CVE details -", e)

    return cve_details_str  # Return the CVE details as a string

def send_email(subject, body, receiver_email, sender_email, smtp_password, smtp_server="smtp.gmail.com", smtp_port=587):
    message = f"Subject: {subject}\n\n{body}"
    
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Upgrade the connection to a secure one
        server.login(sender_email, smtp_password)
        server.sendmail(sender_email, receiver_email, message)

# Call the function to get the CVE details
cve_details_str = get_last_week_published_cve_details(limit=500)

# Send the email using smtplib
send_email(
    subject="Last Week Published  CVE Details",
    body=cve_details_str,
    receiver_email="praveen.sreedharan@ust.com",
    sender_email="praveensreedha@gmail.com",
    smtp_password="vytynthetwwetrah"
)
