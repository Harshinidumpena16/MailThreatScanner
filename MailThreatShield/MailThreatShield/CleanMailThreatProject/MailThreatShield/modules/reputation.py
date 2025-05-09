import logging
import random

logger = logging.getLogger(__name__)

class ReputationChecker:
    """Checks the reputation of email sender, domain, and IP addresses"""
    
    def __init__(self, email_data):
        self.email_data = email_data
        
    def check(self):
        """Check reputation of sender elements"""
        try:
            reputation_results = {}
            
            # Extract sender address
            sender = self.email_data.get("from", "unknown@sender.com")
            
            # Extract domain from sender
            domain = self.extract_domain(sender)
            
            # Extract IP addresses
            ip_addresses = self.email_data.get("ip_addresses", [])
            
            # Check sender reputation
            reputation_results["sender"] = self.check_sender_reputation(sender)
            
            # Check domain reputation
            reputation_results["domain"] = self.check_domain_reputation(domain)
            
            # Check IP reputation
            reputation_results["ip"] = self.check_ip_reputation(ip_addresses)
            
            # Geolocate IP addresses
            reputation_results["geo"] = self.geolocate_ip(ip_addresses)
            
            # Overall reputation score
            reputation_results["overall"] = self.calculate_overall_reputation(reputation_results)
            
            return reputation_results
        
        except Exception as e:
            logger.exception("Error checking reputation")
            return {
                "sender": {"score": 0, "risk": "unknown", "details": str(e)},
                "domain": {"score": 0, "risk": "unknown", "details": str(e)},
                "ip": {"score": 0, "risk": "unknown", "details": str(e)},
                "geo": {"country": "Unknown", "details": str(e)},
                "overall": {"score": 0, "risk": "unknown", "details": str(e)}
            }
    
    def extract_domain(self, email_address):
        """Extract domain from email address"""
        try:
            # Extract everything after @ symbol
            at_pos = email_address.rfind('@')
            if at_pos > 0:
                domain_part = email_address[at_pos + 1:]
                # Remove any trailing angle bracket or whitespace
                domain = domain_part.split('>')[0].strip()
                return domain
            return "unknown"
        except:
            return "unknown"
    
    def check_sender_reputation(self, sender):
        """Check reputation of sender email address"""
        # In a real implementation, this would query reputation databases
        # For this demo, we'll simulate a reputation check
        
        # Extract domain for better simulation
        domain = self.extract_domain(sender)
        
        # Simulated reputation check (would be a real API call in production)
        if "spam" in sender.lower() or "phish" in sender.lower():
            score = 20
            risk = "high"
            details = "Sender address contains suspicious keywords"
        elif domain in ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"]:
            score = 70
            risk = "low"
            details = "Common legitimate email provider"
        elif "unknown" in domain:
            # Further reduce negative impact of unknown domains to eliminate false positives
            score = 75  # Increased from 55 to a much more favorable score
            risk = "low"
            details = "Unknown sender domain - likely due to limited header information"
        else:
            # Random score between 50-90 for demo purposes
            score = random.randint(50, 90)
            risk = "low" if score >= 70 else "medium"
            details = "Sender has no known negative reputation"
        
        return {
            "score": score,
            "risk": risk,
            "details": details
        }
    
    def check_domain_reputation(self, domain):
        """Check reputation of sender domain"""
        # In a real implementation, this would query domain reputation databases
        # For this demo, we'll simulate a reputation check
        
        # Simulated reputation check (would be a real API call in production)
        if "spam" in domain.lower() or "phish" in domain.lower() or "temp" in domain.lower():
            score = 20
            risk = "high"
            details = "Domain contains suspicious keywords"
        elif domain in ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"]:
            score = 75
            risk = "low"
            details = "Common legitimate email provider"
        elif domain == "unknown":
            # Further improve score for unknown domains to eliminate false positives
            score = 75  # Increased from 55 to match consistent scoring
            risk = "low"
            details = "Unknown domain - likely due to limited header information"
        else:
            # Check for suspicious TLDs
            suspicious_tlds = [".xyz", ".top", ".club", ".info", ".site"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                score = 40
                risk = "medium"
                details = f"Domain uses potentially suspicious TLD"
            else:
                # Random score between 60-95 for demo purposes
                score = random.randint(60, 95)
                risk = "low" if score >= 70 else "medium"
                details = "Domain has no known negative reputation"
        
        return {
            "score": score,
            "risk": risk,
            "details": details
        }
    
    def check_ip_reputation(self, ip_addresses):
        """Check reputation of sender IP addresses"""
        # In a real implementation, this would query IP reputation databases
        # For this demo, we'll simulate a reputation check
        
        if not ip_addresses:
            return {
                "score": None,
                "risk": "unknown",
                "details": "IP Address is Not Available",
                "no_ip_found": True
            }
        
        # For demo purposes, just check the first IP
        ip = ip_addresses[0]
        
        # Check for private IP ranges
        if (
            ip.startswith("10.") or 
            ip.startswith("192.168.") or 
            (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
        ):
            score = 60
            risk = "medium"
            details = "Private IP address detected"
        # Check for localhost
        elif ip.startswith("127."):
            score = 30
            risk = "high"
            details = "Localhost IP detected (suspicious)"
        else:
            # Random score between 40-90 for demo purposes
            score = random.randint(40, 90)
            
            if score < 50:
                risk = "high"
                details = "IP address has poor reputation"
            elif score < 70:
                risk = "medium"
                details = "IP address has moderate reputation"
            else:
                risk = "low"
                details = "IP address has good reputation"
        
        return {
            "score": score,
            "risk": risk,
            "details": details,
            "ip": ip
        }
    
    def geolocate_ip(self, ip_addresses):
        """Geolocate IP addresses found in email headers"""
        # In a real implementation, this would use a geolocation service
        # For this demo, we'll simulate geolocation results
        
        if not ip_addresses:
            return {
                "country": "Unknown",
                "city": "Unknown",
                "coordinates": None,
                "details": "No IP addresses found in email headers"
            }
        
        # For demo purposes, just geolocate the first IP
        ip = ip_addresses[0]
        
        # Check for private IP ranges
        if (
            ip.startswith("10.") or 
            ip.startswith("192.168.") or 
            (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31) or
            ip.startswith("127.")
        ):
            return {
                "country": "Local Network",
                "city": "Private IP",
                "coordinates": None,
                "details": "IP is from a private network"
            }
        
        # Sample countries for demo
        countries = ["United States", "United Kingdom", "Germany", "France", 
                    "Russia", "China", "India", "Brazil", "Nigeria"]
        
        # Assign a random country for the demo
        country = random.choice(countries)
        
        # Assign cities based on country
        cities = {
            "United States": ["New York", "Los Angeles", "Chicago", "Houston"],
            "United Kingdom": ["London", "Manchester", "Birmingham", "Glasgow"],
            "Germany": ["Berlin", "Munich", "Hamburg", "Frankfurt"],
            "France": ["Paris", "Marseille", "Lyon", "Toulouse"],
            "Russia": ["Moscow", "Saint Petersburg", "Novosibirsk", "Yekaterinburg"],
            "China": ["Beijing", "Shanghai", "Guangzhou", "Shenzhen"],
            "India": ["Mumbai", "Delhi", "Bangalore", "Hyderabad"],
            "Brazil": ["São Paulo", "Rio de Janeiro", "Brasília", "Salvador"],
            "Nigeria": ["Lagos", "Kano", "Ibadan", "Abuja"]
        }
        
        city = random.choice(cities.get(country, ["Unknown"]))
        
        return {
            "country": country,
            "city": city,
            "coordinates": None,  # Would include latitude/longitude in a real implementation
            "details": f"IP geolocated to {city}, {country}"
        }
    
    def calculate_overall_reputation(self, reputation_results):
        """Calculate overall reputation based on individual scores"""
        sender_score = reputation_results["sender"]["score"]
        domain_score = reputation_results["domain"]["score"]
        ip_score = reputation_results["ip"].get("score")
        
        # If IP score is None (when no IP is found), only use sender and domain scores
        if ip_score is None:
            weighted_score = (sender_score * 0.4) + (domain_score * 0.6)
        else:
            # Weight the scores (domain slightly more important than others)
            weighted_score = (sender_score * 0.3) + (domain_score * 0.4) + (ip_score * 0.3)
        
        # Round to nearest integer
        overall_score = round(weighted_score)
        
        # Determine risk level
        if overall_score < 50:
            risk = "high"
            details = "Sender has poor overall reputation"
        elif overall_score < 70:
            risk = "medium"
            details = "Sender has moderate overall reputation"
        else:
            risk = "low"
            details = "Sender has good overall reputation"
        
        return {
            "score": overall_score,
            "risk": risk,
            "details": details
        }
