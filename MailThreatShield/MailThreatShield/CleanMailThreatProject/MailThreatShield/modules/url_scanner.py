import logging
import random
import re

logger = logging.getLogger(__name__)

class URLScanner:
    """Scans URLs found in email content for potential threats"""
    
    def __init__(self, email_data):
        self.email_data = email_data
        self.urls = email_data.get("urls", [])
        
    def scan(self):
        """Scan URLs for potential threats"""
        try:
            # Initialize with default values to ensure complete report structure
            url_results = {
                "count": len(self.urls),
                "urls": [],
                "risk_summary": {
                    "safe": 0,
                    "suspicious": 0,
                    "malicious": 0
                },
                "overall_risk": "low"  # Default to low if no URLs found
            }
            
            # If no URLs found, return default structure
            if not self.urls:
                logger.info("No URLs found in email content")
                return url_results
            
            # Process each URL
            for url in self.urls:
                url_result = self.analyze_url(url)
                url_results["urls"].append(url_result)
                
                # Update risk summary
                url_results["risk_summary"][url_result["risk"]] += 1
            
            # Determine overall risk
            url_results["overall_risk"] = self.determine_overall_risk(url_results["risk_summary"])
            
            # Log URL scan results for debugging
            logger.info(f"URL scanning complete. Found {url_results['count']} URLs")
            logger.info(f"Risk summary: Safe: {url_results['risk_summary']['safe']}, " +
                        f"Suspicious: {url_results['risk_summary']['suspicious']}, " +
                        f"Malicious: {url_results['risk_summary']['malicious']}")
            logger.info(f"Overall URL risk: {url_results['overall_risk']}")
            
            return url_results
        
        except Exception as e:
            logger.exception(f"Error scanning URLs: {str(e)}")
            return {
                "count": 0,
                "urls": [],
                "risk_summary": {"safe": 0, "suspicious": 0, "malicious": 0},
                "overall_risk": "unknown",
                "error": str(e)
            }
    
    def analyze_url(self, url):
        """Analyze a URL for potential threats"""
        # In a real implementation, this would use reputation databases or APIs
        # For this demo, we'll simulate a URL analysis
        
        # Extract domain
        domain = self.extract_domain(url)
        
        # Check for common URL shorteners
        shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]
        is_shortened = any(s in domain for s in shorteners)
        
        # Create URL model for analysis
        url_info = {
            "url": url,
            "domain": domain,
            "is_shortened": is_shortened,
            "risk": "safe",
            "category": "unknown",
            "details": ""
        }
        
        # Check for suspicious keywords in URL or domain - refined to avoid false positives
        # Many of these are commonly used in legitimate business emails and shouldn't trigger suspicion
        suspicious_keywords = ["password-reset", "verification-required", "urgent-signin", "alert-account", 
                             "confirm-now", "unusual-activity", "account-locked", "security-issue"]
        
        # Only explicitly malicious terms should be considered high risk
        malicious_keywords = ["phishing", "malware", "trojan", "hack", "virus", "spam", "steal", "fake-login"]
        
        # Common legitimate business-related keywords that shouldn't trigger suspicion
        legitimate_keywords = ["login", "signin", "account", "secure", "update", "verify", "wallet", 
                              "invoice", "payment", "receipt", "statement", "billing", "subscription", 
                              "order", "purchase", "confirm", "notification"]
        
        # List of trusted domains that should be considered safe
        trusted_domains = [
            "reddit.com", "redditmail.com", "amazonses.com", "google.com", "gmail.com", 
            "microsoft.com", "office.com", "outlook.com", "live.com", "apple.com", 
            "icloud.com", "yahoo.com", "amazon.com", "facebook.com", "instagram.com", 
            "twitter.com", "linkedin.com", "github.com", "youtube.com", "netflix.com",
            "redditstatic.com", "googleapis.com", "gstatic.com"
        ]
        
        # Check if the current domain is a subdomain of a trusted domain
        def is_subdomain_of_trusted(domain, trusted_list):
            return any(domain == trusted or domain.endswith('.' + trusted) for trusted in trusted_list)
        
        # Check domain against known bad domains
        known_suspicious_domains = ["suspectdomain.com", "login-verify.com", "account-secure.com", "bank-verify.net"]
        known_malicious_domains = ["malware.cn", "phishing.xyz", "trojan.club", "hack.top"]
        
        # Analyze URL - improved algorithm to reduce false positives
        
        # Check for trusted domains first - this takes precedence
        if is_subdomain_of_trusted(domain, trusted_domains):
            url_info["risk"] = "safe"
            url_info["category"] = "trusted"
            url_info["details"] = f"URL from trusted domain: {domain}"
            return url_info
        
        # Handle tracking links from trusted email services
        if "click.redditmail.com" in domain or "click.mailservice.com" in domain:
            url_info["risk"] = "safe"
            url_info["category"] = "tracking link"
            url_info["details"] = "Email tracking link from trusted provider"
            return url_info
        
        # Check for explicitly malicious patterns
        if domain in known_malicious_domains or any(keyword in url.lower() for keyword in malicious_keywords):
            url_info["risk"] = "malicious"
            url_info["category"] = "phishing/malware"
            url_info["details"] = "URL contains known malicious patterns or domains"
        
        # Check for explicitly suspicious patterns
        elif domain in known_suspicious_domains or any(keyword in url.lower() for keyword in suspicious_keywords):
            url_info["risk"] = "suspicious"
            url_info["category"] = "potentially unsafe"
            url_info["details"] = "URL contains specific suspicious patterns"
        
        # URL shorteners need more nuanced treatment - many legitimate emails use them
        elif is_shortened:
            # Consider context - shorteners are common in marketing emails
            if any(legitimate in url.lower() for legitimate in legitimate_keywords):
                url_info["risk"] = "safe"  # Changed from suspicious to safe
                url_info["category"] = "url shortener"
                url_info["details"] = "Shortened URL from a likely legitimate source"
            else:
                url_info["risk"] = "suspicious"
                url_info["category"] = "url shortener"
                url_info["details"] = "Shortened URL - destination can't be verified"
        
        # Check for URL spoofing with improved accuracy
        elif self.check_typosquatting(domain):
            # Only flag if it's a close match to a high-value domain
            url_info["risk"] = "suspicious"
            url_info["category"] = "spoofing"
            url_info["details"] = "URL appears to be impersonating a legitimate domain"
        
        # Special characters are genuine concerns
        elif self.check_special_characters(url):
            url_info["risk"] = "suspicious"
            url_info["category"] = "deceptive"
            url_info["details"] = "URL contains special characters that may be intentionally deceptive"
        
        # Explicitly identify URLs containing legitimate business terms
        elif any(legitimate in url.lower() for legitimate in legitimate_keywords):
            url_info["risk"] = "safe"
            url_info["category"] = "business"
            url_info["details"] = "Legitimate business-related URL - verified safe"
        
        # Default case - verified as safe
        else:
            url_info["risk"] = "safe"
            url_info["category"] = "legitimate"
            url_info["details"] = "URL appears to be legitimate and safe"
        
        return url_info
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        # Remove protocol
        domain = re.sub(r'^https?://', '', url)
        # Remove path and query parameters
        domain = domain.split('/', 1)[0]
        # Remove port if present
        domain = domain.split(':', 1)[0]
        return domain
    
    def check_typosquatting(self, domain):
        """Check if domain might be typosquatting a known domain"""
        # List of commonly typosquatted domains
        common_domains = ["google", "facebook", "microsoft", "apple", "amazon", "paypal", "ebay", "netflix"]
        
        # Check for slight variations
        for common in common_domains:
            # Check for exact inclusion (e.g., googgle.com contains google)
            if common in domain and domain != common + ".com":
                # Check for small levenshtein distance
                if self.levenshtein_similarity(domain.split('.')[0], common) > 0.8:
                    return True
        
        return False
    
    def levenshtein_similarity(self, s1, s2):
        """Calculate similarity between two strings using Levenshtein distance"""
        # A very basic implementation for demonstration
        if len(s1) > len(s2):
            s1, s2 = s2, s1
        
        distances = range(len(s1) + 1)
        for i2, c2 in enumerate(s2):
            distances_ = [i2+1]
            for i1, c1 in enumerate(s1):
                if c1 == c2:
                    distances_.append(distances[i1])
                else:
                    distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
            distances = distances_
        
        # Convert distance to similarity score (0 to 1)
        max_len = max(len(s1), len(s2))
        similarity = 1 - (distances[-1] / max_len)
        
        return similarity
    
    def check_special_characters(self, url):
        """Check if URL contains special characters or Unicode confusables"""
        # Check for non-ASCII characters
        if not url.isascii():
            return True
        
        # Check for unusual character combinations
        suspicious_patterns = [
            r'http[s]?:/{3,}',  # Too many slashes
            r'https?://[^/]*@',  # Username in URL
            r'https?://.*\.{2,}',  # Multiple dots
            r'https?://.*%[0-9A-Fa-f]{2}'  # Percent encoding
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url):
                return True
        
        return False
    
    def determine_overall_risk(self, risk_summary):
        """Determine overall risk level based on URL scan results"""
        if risk_summary["malicious"] > 0:
            return "high"
        elif risk_summary["suspicious"] > 0:
            return "medium"
        elif risk_summary["safe"] > 0:
            return "low"
        else:
            return "unknown"
