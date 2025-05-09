import logging
import random

logger = logging.getLogger(__name__)

class QRScanner:
    """Scans QR codes in email attachments"""
    
    def __init__(self, email_data):
        self.email_data = email_data
        self.attachments = email_data.get("attachments", [])
        
    def scan(self):
        """Scan for QR codes in attachments"""
        try:
            qr_results = {
                "count": 0,
                "qr_codes": [],
                "risk_summary": {
                    "safe": 0,
                    "suspicious": 0,
                    "malicious": 0
                }
            }
            
            # Filter for image attachments that might contain QR codes
            image_attachments = [
                attachment for attachment in self.attachments
                if self.is_image(attachment)
            ]
            
            # Process each image attachment
            for attachment in image_attachments:
                # In a real implementation, this would use QR code detection libraries
                # For this demo, we'll simulate QR code detection and analysis
                qr_code = self.detect_qr_code(attachment)
                
                if qr_code:
                    qr_results["count"] += 1
                    qr_results["qr_codes"].append(qr_code)
                    
                    # Update risk summary
                    qr_results["risk_summary"][qr_code["risk"]] += 1
            
            # Determine overall risk
            qr_results["overall_risk"] = self.determine_overall_risk(qr_results["risk_summary"])
            
            return qr_results
        
        except Exception as e:
            logger.exception("Error scanning QR codes")
            return {
                "count": 0,
                "qr_codes": [],
                "risk_summary": {"safe": 0, "suspicious": 0, "malicious": 0},
                "overall_risk": "unknown",
                "error": str(e)
            }
    
    def is_image(self, attachment):
        """Check if an attachment is an image that might contain QR codes"""
        content_type = attachment.get("content_type", "")
        filename = attachment.get("filename", "")
        
        # Check content type
        if content_type.startswith("image/"):
            return True
        
        # Check filename extension
        image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"]
        return any(filename.lower().endswith(ext) for ext in image_extensions)
    
    def detect_qr_code(self, attachment):
        """Detect QR codes in an image attachment"""
        # In a real implementation, this would use a QR code scanning library
        # For this demo, we'll simulate QR code detection with a probability
        
        filename = attachment.get("filename", "unknown")
        
        # Simulate QR code detection (30% chance of finding a QR code)
        if random.random() < 0.3:
            # Create a simulated QR code result
            qr_code = {
                "attachment_filename": filename,
                "detected": True,
                "content": self.generate_qr_content(),
                "content_type": "url",  # url, text, contact, wifi, etc.
                "risk": "safe",
                "details": ""
            }
            
            # Analyze the QR code content
            self.analyze_qr_content(qr_code)
            
            return qr_code
        
        return None
    
    def generate_qr_content(self):
        """Generate simulated QR code content for demo purposes"""
        # Generate different types of QR content with weighted probabilities
        content_types = [
            # (type, weight, generator function)
            ("url", 0.7, self.generate_url),
            ("text", 0.2, self.generate_text),
            ("contact", 0.05, self.generate_contact),
            ("wifi", 0.05, self.generate_wifi)
        ]
        
        # Choose content type based on weights
        r = random.random()
        cumulative = 0
        for content_type, weight, generator in content_types:
            cumulative += weight
            if r <= cumulative:
                return generator()
        
        # Default fallback
        return self.generate_url()
    
    def generate_url(self):
        """Generate a simulated URL for a QR code"""
        # Common domains
        domains = [
            "example.com", "google.com", "somebank.com", "payment-portal.com",
            "bit.ly/2x3Z5a", "tinyurl.com/y8dh2s", "login-verify.net"
        ]
        
        # Paths
        paths = [
            "", "/login", "/verify", "/account", "/secure", "/password-reset",
            "/invoice/123", "/document/view", "/payment/confirm"
        ]
        
        domain = random.choice(domains)
        path = random.choice(paths)
        
        return f"https://{domain}{path}"
    
    def generate_text(self):
        """Generate simulated text content for a QR code"""
        texts = [
            "Your package will be delivered tomorrow. Track at: https://delivery-track.com/123456",
            "Your account needs verification. Please login at secure-bank.com",
            "Call this number for support: +1-555-123-4567",
            "Your invoice #12345 is attached. Please process payment.",
            "Meeting ID: 123-456-789, Password: securepass"
        ]
        
        return random.choice(texts)
    
    def generate_contact(self):
        """Generate simulated contact information for a QR code"""
        # vCard format
        names = ["John Smith", "Jane Doe", "Tech Support", "Account Services"]
        
        name = random.choice(names)
        phone = f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}"
        email = f"{name.lower().replace(' ', '.')}@example.com"
        
        return f"BEGIN:VCARD\nVERSION:3.0\nN:{name}\nTEL:{phone}\nEMAIL:{email}\nEND:VCARD"
    
    def generate_wifi(self):
        """Generate simulated WiFi credentials for a QR code"""
        ssids = ["Home WiFi", "Free Public WiFi", "Airport WiFi", "Conference WiFi", "Hotel Guest"]
        passwords = ["password123", "secure!pass", "Guest1234", "WiFi@2023"]
        
        ssid = random.choice(ssids)
        password = random.choice(passwords)
        
        return f"WIFI:S:{ssid};T:WPA;P:{password};;"
    
    def analyze_qr_content(self, qr_code):
        """Analyze QR code content for potential threats"""
        content = qr_code["content"]
        
        # For URLs, check for suspicious or malicious patterns
        if content.startswith("http"):
            qr_code["content_type"] = "url"
            
            # Check for URL shorteners
            shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]
            is_shortened = any(s in content for s in shorteners)
            
            # Check for suspicious domains or paths
            suspicious_patterns = [
                "login", "signin", "account", "secure", "verify", "password",
                "bank", "paypal", "wallet", "invoice", "payment"
            ]
            
            malicious_patterns = [
                "malware", "trojan", "hack", "phish", "spam", "scam"
            ]
            
            if any(pattern in content.lower() for pattern in malicious_patterns):
                qr_code["risk"] = "malicious"
                qr_code["details"] = "QR code contains a URL with malicious patterns"
            
            elif is_shortened:
                qr_code["risk"] = "suspicious"
                qr_code["details"] = "QR code contains a shortened URL, destination unknown"
            
            elif any(pattern in content.lower() for pattern in suspicious_patterns):
                qr_code["risk"] = "suspicious"
                qr_code["details"] = "QR code contains a URL with suspicious patterns"
            
            else:
                qr_code["risk"] = "safe"
                qr_code["details"] = "QR code contains a URL with no suspicious patterns"
        
        # For text content, check for suspicious patterns
        elif "BEGIN:VCARD" in content:
            qr_code["content_type"] = "contact"
            
            # Check for suspicious contact information
            suspicious_titles = ["tech support", "account", "security", "bank", "payment"]
            
            if any(title in content.lower() for title in suspicious_titles):
                qr_code["risk"] = "suspicious"
                qr_code["details"] = "QR code contains contact information with suspicious job titles"
            else:
                qr_code["risk"] = "safe"
                qr_code["details"] = "QR code contains contact information with no suspicious patterns"
        
        # For WiFi credentials
        elif content.startswith("WIFI:"):
            qr_code["content_type"] = "wifi"
            
            # WiFi credentials are generally not malicious on their own
            # but could be used to connect to rogue networks
            if "Free" in content or "Public" in content:
                qr_code["risk"] = "suspicious"
                qr_code["details"] = "QR code contains credentials for a public WiFi network"
            else:
                qr_code["risk"] = "safe"
                qr_code["details"] = "QR code contains WiFi network credentials"
        
        # For other text content
        else:
            qr_code["content_type"] = "text"
            
            # Check for suspicious text patterns
            suspicious_patterns = [
                "urgent", "password", "verify", "account", "login", "bank",
                "click", "link", "call", "immediately", "security"
            ]
            
            if any(pattern in content.lower() for pattern in suspicious_patterns):
                qr_code["risk"] = "suspicious"
                qr_code["details"] = "QR code contains text with suspicious patterns"
            else:
                qr_code["risk"] = "safe"
                qr_code["details"] = "QR code contains text with no suspicious patterns"
    
    def determine_overall_risk(self, risk_summary):
        """Determine overall risk level based on QR code scan results"""
        if risk_summary["malicious"] > 0:
            return "high"
        elif risk_summary["suspicious"] > 0:
            return "medium"
        elif risk_summary["safe"] > 0:
            return "low"
        else:
            return "unknown"
