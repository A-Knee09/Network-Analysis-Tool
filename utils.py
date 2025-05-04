from fpdf import FPDF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import csv
import os
import time
import socket
from datetime import datetime


def export_to_pdf(protocol_count, interface, filename="report.pdf"):
    """Export statistics to a PDF report with improved formatting."""
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Add a cover page
        pdf.add_page()
        pdf.set_font("Arial", "B", 24)
        pdf.cell(0, 20, "Network Traffic Analysis Report", ln=True, align="C")
        
        # Add timestamp and interface info
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.cell(0, 10, f"Interface: {interface}", ln=True, align="C")
        
        # Add system info
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "System Information", ln=True)
        
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Hostname: {socket.gethostname()}", ln=True)
        pdf.cell(0, 8, f"Operating System: {os.name}", ln=True)
        
        # Packet statistics page
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Packet Statistics", ln=True)
        
        # Create a table
        pdf.set_font("Arial", "B", 10)
        
        # Table headers
        col_width = 60
        row_height = 10
        pdf.cell(col_width, row_height, "Protocol", border=1)
        pdf.cell(col_width, row_height, "Count", border=1)
        pdf.cell(col_width, row_height, "Percentage", border=1, ln=True)
        
        # Calculate total packets
        total_packets = sum(protocol_count.values())
        
        # Table data
        pdf.set_font("Arial", "", 10)
        for protocol, count in protocol_count.items():
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            pdf.cell(col_width, row_height, protocol, border=1)
            pdf.cell(col_width, row_height, str(count), border=1)
            pdf.cell(col_width, row_height, f"{percentage:.2f}%", border=1, ln=True)
        
        # Total row
        pdf.set_font("Arial", "B", 10)
        pdf.cell(col_width, row_height, "Total", border=1)
        pdf.cell(col_width, row_height, str(total_packets), border=1)
        pdf.cell(col_width, row_height, "100.00%", border=1, ln=True)
        
        # Add some analysis text
        pdf.ln(10)
        pdf.set_font("Arial", "", 12)
        pdf.multi_cell(0, 8, "Analysis Summary:\n\n"
                         "This report provides a summary of network traffic captured on the selected interface. "
                         "The protocol distribution shows the relative frequency of different protocols in the captured data.")
        
        # Add recommendations section
        pdf.ln(5)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Recommendations", ln=True)
        
        pdf.set_font("Arial", "", 10)
        if protocol_count.get("TCP", 0) > protocol_count.get("UDP", 0) * 3:
            pdf.multi_cell(0, 8, "The traffic is primarily TCP-based, which suggests application-level communications "
                              "such as web browsing, email, or file transfers.")
        
        if protocol_count.get("UDP", 0) > protocol_count.get("TCP", 0):
            pdf.multi_cell(0, 8, "High UDP traffic might indicate streaming media, VoIP, DNS lookups, or gaming applications.")
        
        if protocol_count.get("ICMP", 0) > total_packets * 0.1:
            pdf.multi_cell(0, 8, "The high proportion of ICMP traffic might indicate network troubleshooting "
                              "activities (ping, traceroute) or potential ping-based attacks.")
        
        # Add footer with page numbers
        pdf.alias_nb_pages()
        
        # Output the PDF
        pdf.output(filename)
        return True
    except Exception as e:
        raise Exception(f"Failed to generate PDF: {str(e)}")


def send_email(report_file, recipient, subject="Network Analysis Report"):
    """Email the PDF report with improved error handling."""
    try:
        # Get email credentials from environment or use defaults
        email_from = os.getenv("EMAIL_FROM", "your_email@example.com")
        email_password = os.getenv("EMAIL_PASSWORD", "")
        smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        
        # Create message
        msg = MIMEMultipart()
        msg["From"] = email_from
        msg["To"] = recipient
        msg["Subject"] = subject
        
        # Add message body
        body = (
            "Please find attached the Network Analysis Report.\n\n"
            "This report contains statistics on network traffic captured with the Network Analysis Tool."
        )
        msg.attach(MIMEText(body, "plain"))
        
        # Attach the PDF file
        with open(report_file, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition", f"attachment; filename={os.path.basename(report_file)}"
            )
            msg.attach(part)
        
        # Check if we have valid credentials
        if not email_password:
            return "Email credentials not configured. Please set the EMAIL_PASSWORD environment variable."
        
        # Send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_from, email_password)
            server.send_message(msg)
            
        return True
    except Exception as e:
        return str(e)