import logging
import re

logger = logging.getLogger(__name__)

class AuthChecker:
    """Checks email authentication data (SPF, DKIM, DMARC)"""
    
    def __init__(self, email_data):
        self.email_data = email_data
        
    def check(self):
        """Check email authentication results"""
        try:
            auth_results = {}
            
            # Extract SPF results
            auth_results["spf"] = self.check_spf()
            
            # Extract DKIM results
            auth_results["dkim"] = self.check_dkim()
            
            # Extract DMARC results
            auth_results["dmarc"] = self.check_dmarc()
            
            # Overall authentication status
            auth_results["overall"] = self.determine_overall_status(auth_results)
            
            return auth_results
        
        except Exception as e:
            logger.exception("Error checking email authentication")
            return {
                "spf": {"status": "error", "details": str(e)},
                "dkim": {"status": "error", "details": str(e)},
                "dmarc": {"status": "error", "details": str(e)},
                "overall": {"status": "error", "details": str(e)}
            }
    
    def check_spf(self):
        """Check SPF authentication results"""
        # Check Authentication-Results header for SPF
        auth_results = self.email_data.get("auth_results", "")
        
        # Pattern to match SPF results
        spf_pattern = r'spf=(\w+)'
        spf_match = re.search(spf_pattern, auth_results, re.IGNORECASE)
        
        if spf_match:
            spf_result = spf_match.group(1).lower()
            
            # Map SPF result to status
            if spf_result in ['pass']:
                status = "pass"
                details = "SPF authentication passed"
            elif spf_result in ['neutral']:
                status = "neutral"
                details = "SPF check returned neutral"
            elif spf_result in ['fail', 'softfail']:
                status = "fail"
                details = "SPF authentication failed"
            else:
                status = "unknown"
                details = f"Unknown SPF result: {spf_result}"
        else:
            # No SPF results found, check Received-SPF header as fallback
            received_spf = self.email_data.get("headers", {}).get("Received-SPF", "")
            
            if "pass" in received_spf.lower():
                status = "pass"
                details = "SPF authentication passed"
            elif "neutral" in received_spf.lower():
                status = "neutral"
                details = "SPF check returned neutral"
            elif "fail" in received_spf.lower() or "softfail" in received_spf.lower():
                status = "fail"
                details = "SPF authentication failed"
            else:
                status = "unknown"
                details = "No SPF information found"
        
        return {
            "status": status,
            "details": details
        }
    
    def check_dkim(self):
        """Check DKIM authentication results"""
        # Check Authentication-Results header for DKIM
        auth_results = self.email_data.get("auth_results", "")
        
        # Pattern to match DKIM results
        dkim_pattern = r'dkim=(\w+)'
        dkim_match = re.search(dkim_pattern, auth_results, re.IGNORECASE)
        
        if dkim_match:
            dkim_result = dkim_match.group(1).lower()
            
            # Map DKIM result to status
            if dkim_result in ['pass']:
                status = "pass"
                details = "DKIM signature verified"
            elif dkim_result in ['neutral']:
                status = "neutral"
                details = "DKIM check returned neutral"
            elif dkim_result in ['fail', 'permerror', 'temperror']:
                status = "fail"
                details = "DKIM verification failed"
            else:
                status = "unknown"
                details = f"Unknown DKIM result: {dkim_result}"
        else:
            # Search for DKIM-Signature header as fallback
            dkim_signature = any(k.startswith("DKIM-Signature") for k in self.email_data.get("headers", {}))
            
            if dkim_signature:
                status = "unknown"
                details = "DKIM signature present but verification status unknown"
            else:
                status = "missing"
                details = "No DKIM signature found"
        
        return {
            "status": status,
            "details": details
        }
    
    def check_dmarc(self):
        """Check DMARC authentication results"""
        # Check Authentication-Results header for DMARC
        auth_results = self.email_data.get("auth_results", "")
        
        # Pattern to match DMARC results
        dmarc_pattern = r'dmarc=(\w+)'
        dmarc_match = re.search(dmarc_pattern, auth_results, re.IGNORECASE)
        
        if dmarc_match:
            dmarc_result = dmarc_match.group(1).lower()
            
            # Map DMARC result to status
            if dmarc_result in ['pass']:
                status = "pass"
                details = "DMARC check passed"
            elif dmarc_result in ['bestguesspass']:
                status = "pass"
                details = "DMARC passed (best guess)"
            elif dmarc_result in ['fail']:
                status = "fail"
                details = "DMARC check failed"
            else:
                status = "unknown"
                details = f"Unknown DMARC result: {dmarc_result}"
        else:
            # Extract domain from sender and check for DMARC policy
            from_address = self.email_data.get("from", "")
            
            # Extract domain from email address
            domain_match = re.search(r'@([^>]+)', from_address)
            if domain_match:
                domain = domain_match.group(1)
                status = "unknown"
                details = f"No DMARC result found for domain {domain}"
            else:
                status = "unknown"
                details = "No DMARC information found"
        
        return {
            "status": status,
            "details": details
        }
    
    def determine_overall_status(self, auth_results):
        """Determine overall authentication status"""
        spf_status = auth_results["spf"]["status"]
        dkim_status = auth_results["dkim"]["status"]
        dmarc_status = auth_results["dmarc"]["status"]
        
        # Check if all statuses are "unknown" or "missing" which indicates limited header information
        all_unknown = all(s in ["unknown", "missing"] for s in [spf_status, dkim_status, dmarc_status])
        
        # If all authentication information is unknown/missing, keep the status as unknown
        if all_unknown:
            status = "unknown"  # Changed back to "unknown" when all authentication methods are unknown
            details = "Authentication information unavailable"
        
        # If any authentication method fails, overall status is fail
        elif "fail" in [spf_status, dkim_status, dmarc_status]:
            # Count how many failures vs unknowns
            fail_count = [spf_status, dkim_status, dmarc_status].count("fail")
            unknown_count = sum(1 for s in [spf_status, dkim_status, dmarc_status] if s in ["unknown", "missing"])
            
            # If there's only one failure and the rest are unknown, be much more lenient
            if fail_count == 1 and unknown_count == 2:
                status = "pass"  # Changed from "partial" to "pass" to further reduce false positives
                details = "Limited authentication data available, treating as legitimate despite partial failure"
            else:
                status = "fail"
                details = "One or more authentication checks failed"
        
        # If all methods pass, overall status is pass
        elif all(s == "pass" for s in [spf_status, dkim_status, dmarc_status]):
            status = "pass"
            details = "All authentication checks passed"
        
        # If some pass and others are neutral or unknown
        elif "pass" in [spf_status, dkim_status, dmarc_status]:
            status = "partial"
            details = "Some authentication checks passed, others inconclusive"
        
        # If all are neutral - be more lenient
        elif all(s == "neutral" for s in [spf_status, dkim_status, dmarc_status]):
            status = "partial"  # Changed from "unknown" to "partial" for consistency
            details = "All authentication checks were neutral - treating as partially verified"
        
        # If mix of neutral and unknown - treat more favorably
        else:
            status = "partial"  # Changed from "unknown" to "partial" to reduce false positives
            details = "Authentication status is mixed or neutral - treating as partially verified"
        
        return {
            "status": status,
            "details": details
        }
