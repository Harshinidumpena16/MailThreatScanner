import logging

logger = logging.getLogger(__name__)

class VerdictEngine:
    """Determines overall verdict for email security analysis"""
    
    def __init__(self, auth_results, reputation_results, url_results, 
                 attachment_results, qr_results, audio_results, email_data=None):
        self.auth_results = auth_results
        self.reputation_results = reputation_results
        self.url_results = url_results
        self.attachment_results = attachment_results
        self.qr_results = qr_results
        self.audio_results = audio_results
        self.email_data = email_data or {}
        
    def get_verdict(self):
        """
        Generate a final verdict for the email based on improved classification rules:
        - If ANY component has high risk → Malicious
        - If ANY component has medium risk → Suspicious
        - If ALL components have low risk → Safe
        
        With enhanced context awareness to reduce false positives
        """
        try:
            # Store risk levels for each component
            component_risks = {}
            
            # Authentication risk with improved false positive handling
            auth_status = self.auth_results.get("overall", {}).get("status", "unknown")
            if auth_status == "fail":
                # Check if this is from a major provider (likely trustworthy despite auth issues)
                email_domain = self.extract_domain_from_email(self.email_data.get("from", "unknown@example.com"))
                major_providers = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com", 
                                  "icloud.com", "redditmail.com", "amazonses.com", "mail.com"]
                
                if email_domain in major_providers:
                    # For major providers, downgrade high risk to medium - they often have custom auth setups
                    component_risks["auth"] = "medium"
                    logger.info(f"Downgraded auth risk for trusted provider: {email_domain}")
                else:
                    component_risks["auth"] = "high"
            elif auth_status == "partial":
                component_risks["auth"] = "medium"
            else:  # pass, unknown, error
                component_risks["auth"] = "low"
            
            # Reputation risk (convert score to risk level)
            reputation_score = self.reputation_results.get("overall", {}).get("score", 50)
            if reputation_score < 30:  # Poor reputation
                component_risks["reputation"] = "high"
            elif reputation_score < 60:  # Medium reputation
                component_risks["reputation"] = "medium"
            else:  # Good reputation
                component_risks["reputation"] = "low"
            
            # URL risk (map to our risk levels)
            url_risk = self.url_results.get("overall_risk", "unknown")
            url_count = self.url_results.get("count", 0)
            
            # If no URLs, set risk to low
            if url_count == 0:
                component_risks["urls"] = "low"
                logger.info("No URLs found, setting URL risk to low")
            else:
                if url_risk == "high":
                    component_risks["urls"] = "high"
                elif url_risk == "medium":
                    component_risks["urls"] = "medium"
                else:  # low, unknown
                    component_risks["urls"] = "low"
            
            # Attachment risk
            attachment_risk = self.attachment_results.get("overall_risk", "unknown")
            attachment_count = len(self.email_data.get("attachments", []))
            
            # If no attachments, set risk to low
            if attachment_count == 0:
                component_risks["attachments"] = "low"
                logger.info("No attachments found, setting attachment risk to low")
            else:
                if attachment_risk == "high":
                    component_risks["attachments"] = "high"
                elif attachment_risk == "medium":
                    component_risks["attachments"] = "medium"
                else:  # low, unknown
                    component_risks["attachments"] = "low"
            
            # QR code risk
            qr_risk = self.qr_results.get("overall_risk", "unknown")
            qr_count = self.qr_results.get("count", 0)
            
            # If no QR codes, set risk to low
            if qr_count == 0:
                component_risks["qr"] = "low"
            else:
                if qr_risk == "high":
                    component_risks["qr"] = "high"
                elif qr_risk == "medium":
                    component_risks["qr"] = "medium"
                else:  # low, unknown
                    component_risks["qr"] = "low"
            
            # Audio risk
            audio_risk = self.audio_results.get("overall_risk", "unknown")
            audio_count = self.audio_results.get("count", 0)
            
            # If no audio attachments, set risk to low
            if audio_count == 0:
                component_risks["audio"] = "low"
            else:
                if audio_risk == "high":
                    component_risks["audio"] = "high"
                elif audio_risk == "medium":
                    component_risks["audio"] = "medium"
                else:  # low, unknown
                    component_risks["audio"] = "low"
            
            # Determine the final verdict based on enhanced rules:
            # If ANY component is high risk → Malicious
            # If ANY component is medium risk → Suspicious
            # If ALL components are low risk → Safe
            
            # Context-aware risk assessment - look at which components have risks
            has_high_risk = any(risk == "high" for risk in component_risks.values())
            has_medium_risk = any(risk == "medium" for risk in component_risks.values())
            
            # Add context information to improve verdict accuracy
            email_subject = self.email_data.get("subject", "").lower()
            sender = self.email_data.get("from", "").lower()
            
            # Log the component risks for debugging
            logger.info(f"Component risks: {component_risks}")
            
            # Determine risk level based on component risks and context
            if has_high_risk:
                final_risk = "high"
                score = 85
            elif has_medium_risk:
                # Check if this is likely a legitimate email with medium risk components
                likely_legitimate = False
                # Check if from a known legitimate sender
                trusted_domains = [
                    "reddit.com", "redditmail.com", "amazonses.com", "google.com", "gmail.com",
                    "microsoft.com", "office.com", "outlook.com", "live.com", "apple.com", 
                    "icloud.com", "yahoo.com", "amazon.com", "facebook.com", "instagram.com", 
                    "twitter.com", "linkedin.com", "github.com", "youtube.com", "netflix.com",
                    "redditstatic.com", "googleapis.com", "gstatic.com"
                ]
                # Also check for tracking/click domains from trusted providers
                tracking_domains = ["click.redditmail.com", "click.mailservice.com", "email.amazonses.com"]
                
                # Check if the sender email contains any of the trusted domains
                if any(domain in sender for domain in trusted_domains) or any(domain in sender for domain in tracking_domains):
                    likely_legitimate = True
                    logger.info(f"Treating as likely legitimate due to trusted sender: {sender}")
                
                # Special case for Reddit emails with tracking links classified as suspicious
                if "reddit" in sender.lower() and component_risks["urls"] == "medium":
                    # If all URL risk comes from tracking/click links, consider it safe
                    suspicious_count = self.url_results.get("risk_summary", {}).get("suspicious", 0)
                    total_urls = self.url_results.get("count", 0)
                    
                    # If all URLs are marked suspicious and it's from a trusted sender, downgrade URL risk
                    if suspicious_count == total_urls:
                        component_risks["urls"] = "low"
                        logger.info(f"Downgraded URL risk for trusted sender with tracking links: {sender}")
                
                # Maintain medium risk if truly suspicious
                if not likely_legitimate:
                    final_risk = "medium"
                    score = 60
                else:
                    final_risk = "low"
                    score = 35
            else:
                final_risk = "low"
                score = 25
            
            # Create the final verdict
            verdict = self.create_verdict_dictionary(final_risk, score)
            
            # Add component risks for detailed reporting
            verdict["component_risks"] = component_risks
            
            # For backwards compatibility
            component_scores = self.convert_risks_to_scores(component_risks)
            verdict["component_scores"] = component_scores
            
            # Enhance the verdict with more specific details based on findings
            self.enhance_verdict_details(verdict)
            
            # Log the verdict determination for debugging
            logger.info(f"URL Risk: {url_risk}, Attachment Risk: {attachment_risk}")
            logger.info(f"Final verdict: {verdict['verdict']} (level: {verdict['level']})")
            
            return verdict
        
        except Exception as e:
            logger.exception(f"Error generating verdict: {str(e)}")
            return {
                "level": "unknown",
                "score": 50,
                "verdict": "Error generating verdict",
                "details": str(e),
                "recommendations": ["Error in verdict engine"]
            }
            
    def extract_domain_from_email(self, email):
        """Extract domain from email address"""
        try:
            return email.split('@')[1].lower()
        except:
            return "unknown.com"
    
    def enhance_verdict_details(self, verdict):
        """Add more specific details to the verdict based on findings"""
        if verdict["level"] == "malicious":
            # Add specific details about why it's malicious
            malicious_components = [k for k, v in verdict["component_risks"].items() if v == "high"]
            if malicious_components:
                verdict["details"] += f" Potentially dangerous elements found in: {', '.join(malicious_components)}."
        
        elif verdict["level"] == "suspicious":
            # Add specific details about why it's suspicious
            suspicious_components = [k for k, v in verdict["component_risks"].items() if v == "medium"]
            if suspicious_components:
                verdict["details"] += f" Requires caution due to: {', '.join(suspicious_components)}."
        
        # Add recommendations based on specific findings
        if verdict["component_risks"].get("urls") in ["medium", "high"]:
            verdict["recommendations"].append("Avoid clicking links in this email unless you're absolutely sure they're safe")
        
        if verdict["component_risks"].get("attachments") in ["medium", "high"]:
            verdict["recommendations"].append("Do not open attachments from this email")
            
        return verdict
    
    def create_verdict_dictionary(self, risk_level, score):
        """Create a verdict dictionary based on the risk level"""
        verdict = {
            "score": score,
            "level": "",
            "verdict": "",
            "details": "",
            "recommendations": []
        }
        
        if risk_level == "high":
            verdict["level"] = "malicious"
            verdict["verdict"] = "Malicious"
            verdict["details"] = "This email is likely malicious and should not be trusted."
            verdict["recommendations"] = [
                "Do not respond to this email",
                "Do not click any links or open any attachments",
                "Delete this email immediately",
                "Report this email as phishing to your IT department"
            ]
        
        elif risk_level == "medium":
            verdict["level"] = "suspicious"
            verdict["verdict"] = "Suspicious"
            verdict["details"] = "This email has some suspicious characteristics."
            verdict["recommendations"] = [
                "Handle with caution",
                "Verify the sender's identity through another channel",
                "Do not click on links or open attachments unless absolutely sure",
                "Check for unusual spelling, grammar, or formatting"
            ]
        
        else:  # risk_level == "low"
            verdict["level"] = "safe"
            verdict["verdict"] = "Safe"
            verdict["details"] = "This email appears to be legitimate and safe."
            verdict["recommendations"] = ["No suspicious characteristics detected."]
        
        return verdict
    
    def convert_risks_to_scores(self, component_risks):
        """Convert risk levels to scores for backwards compatibility"""
        component_scores = {}
        
        risk_to_score = {
            "low": 20,
            "medium": 55,
            "high": 90
        }
        
        for component, risk in component_risks.items():
            component_scores[component] = risk_to_score.get(risk, 30)
        
        return component_scores
    
    # Keep these methods for backwards compatibility
    def map_auth_score(self, status):
        """Map authentication status to risk score"""
        status_map = {
            "pass": 0,
            "partial": 30,
            "fail": 90,
            "unknown": 30,
            "error": 30
        }
        return status_map.get(status, 30)
    
    def map_risk_score(self, risk_level):
        """Map risk level to score"""
        risk_map = {
            "low": 20,
            "medium": 55,
            "high": 90,
            "unknown": 30
        }
        return risk_map.get(risk_level, 30)
