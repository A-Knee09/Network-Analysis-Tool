from fpdf import FPDF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import csv


def export_to_pdf(protocol_count, filename="report.pdf"):
    """Export statistics to a PDF report."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Packet Statistics Report", ln=True, align="C")
    for protocol, count in protocol_count.items():
        pdf.cell(200, 10, txt=f"{protocol}: {count}", ln=True)
    pdf.output(filename)


def send_email(report_file, recipient):
    """Email the PDF report."""
    msg = MIMEMultipart()
    msg["From"] = "your_email@example.com"
    msg["To"] = recipient
    msg["Subject"] = "Packet Statistics Report"

    with open(report_file, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={report_file}")
        msg.attach(part)

    with smtplib.SMTP("smtp.example.com", 587) as server:
        server.starttls()
        server.login("your_email@example.com", "your_password")
        server.send_message(msg)


