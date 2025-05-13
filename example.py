import subprocess
import re
import requests
import smtplib
import logging
from email.mime.text import MIMEText
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Configure logging
logging.basicConfig(
    filename="dns_monitor.log", 
    level=logging.INFO, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logging.info("DNS Monitoring Started")  # Log the start of the monitoring script

# Function to retrieve connected IPs using the ARP table
def get_connected_devices():
    """Retrieve IPs from the ARP table."""
    try:
        output = subprocess.check_output("arp -a", shell=True)
        output = output.decode()
        # Extract IP addresses using regex
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_addresses = re.findall(ip_pattern, output)
        return ip_addresses
    except subprocess.CalledProcessError as e:
        return []

# Function to retrieve IPs from the DNS cache
def get_dns_cache_ips():
    """Retrieve IPs from the DNS cache."""
    try:
        output = subprocess.check_output("ipconfig /displaydns", shell=True)
        output = output.decode()
        # Extract IP addresses using regex
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_addresses = re.findall(ip_pattern, output)
        return list(set(ip_addresses))  # Remove duplicates
    except subprocess.CalledProcessError as e:
        return []

# Function to check an IP address against VirusTotal
def check_threat(api_key, ip):
    """Check if an IP is malicious using VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_votes = analysis_stats.get('malicious', 0)
            harmless_votes = analysis_stats.get('harmless', 0)

            last_analysis_results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            detailed_report = [
                f"Engine: {engine}, Result: {details['result'] or 'No Threat Detected'}"
                for engine, details in last_analysis_results.items()
                if details.get('result')
            ]

            return {
                "malicious_votes": malicious_votes,
                "harmless_votes": harmless_votes,
                "detailed_report": detailed_report,
            }
        else:
            return None
    except requests.RequestException as e:
        return None

# Function to send email alerts
def send_email_alert(subject, body, recipient):
    sender = "231553@students.au.edu.pk"
    password = "uqcn uszr rwki jmms"  # Replace with your email's app password
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
    except Exception as e:
        pass

# Main GUI Application
class DNSMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Monitor")

        # API Key and Email
        
        self.email_label = tk.Label(root, text="Recipient Email:")
        self.email_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.email_entry = tk.Entry(root, width=50)
        self.email_entry.grid(row=1, column=1, padx=5, pady=5)

        # Output Console
        self.output_label = tk.Label(root, text="Output:")
        self.output_label.grid(row=2, column=0, sticky="nw", padx=5, pady=5)
        self.output_text = scrolledtext.ScrolledText(root, width=60, height=20)
        self.output_text.grid(row=2, column=1, padx=5, pady=5)

        # Buttons
        self.scan_button = tk.Button(root, text="Scan Network", command=self.scan_network)
        self.scan_button.grid(row=3, column=0, padx=5, pady=5)
        self.exit_button = tk.Button(root, text="Exit", command=root.quit)
        self.exit_button.grid(row=3, column=1, padx=5, pady=5, sticky="e")

    def log_output(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

    def scan_network(self):
        api_key = '797e14959102172e9bf83b9aa5584df349c355472c2fa63046c171db21812792'
        recipient_email = self.email_entry.get()

        if not api_key or not recipient_email:
            messagebox.showerror("Error", "API Key and Recipient Email are required!")
            return

        self.log_output("Scanning network for devices...")
        ip_addresses = get_connected_devices()
        dns_cache_ips = get_dns_cache_ips()

        if not ip_addresses and not dns_cache_ips:
            self.log_output("No devices or DNS cache entries found.")
            return

        self.log_output(f"Found {len(ip_addresses)} devices and {len(dns_cache_ips)} DNS cache entries. Checking threats...\n")
        all_ips = set(ip_addresses + dns_cache_ips)  # Combine and deduplicate
        malicious_ips = []

        for ip in all_ips:
            self.log_output(f"Checking IP: {ip}")
            threat_info = check_threat(api_key, ip)
            if threat_info:
                if threat_info["malicious_votes"] > 0:
                    self.log_output(f"Result: {ip} is **Malicious**")
                    malicious_ips.append({
                        "ip": ip,
                        "malicious_votes": threat_info["malicious_votes"],
                        "harmless_votes": threat_info["harmless_votes"],
                        "detailed_report": threat_info["detailed_report"],
                    })
                else:
                    self.log_output(f"Result: {ip} is Not Malicious")
            else:
                self.log_output(f"Failed to retrieve threat data for IP: {ip}")

        if malicious_ips:
            self.log_output("\nGenerating detailed email report...")
            report = "Malicious IP Report\n\n"
            for entry in malicious_ips:
                report += f"IP Address: {entry['ip']}\n"
                report += f"Malicious Votes: {entry['malicious_votes']}\n"
                report += f"Harmless Votes: {entry['harmless_votes']}\n"
                report += "Detailed Analysis:\n"
                report += "\n".join(entry["detailed_report"])
                report += "\n\n"

            subject = "Alert: Malicious IPs Detected on Network"
            send_email_alert(subject, report, recipient_email)
            self.log_output("Report sent via email.")
        else:
            self.log_output("No malicious IPs detected.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSMonitorApp(root)
    root.mainloop()
