import logging
import random

logger = logging.getLogger(__name__)

class AudioAnalyzer:
    """Analyzes audio files in email attachments for potential vishing threats"""
    
    def __init__(self, email_data):
        self.email_data = email_data
        self.attachments = email_data.get("attachments", [])
        
    def analyze(self):
        """Analyze audio files for potential threats"""
        try:
            audio_results = {
                "count": 0,
                "audio_files": [],
                "risk_summary": {
                    "safe": 0,
                    "suspicious": 0,
                    "malicious": 0
                }
            }
            
            # Filter for audio attachments
            audio_attachments = [
                attachment for attachment in self.attachments
                if self.is_audio(attachment)
            ]
            
            # Process each audio attachment
            for attachment in audio_attachments:
                # In a real implementation, this would use speech recognition
                # For this demo, we'll simulate audio analysis
                audio_analysis = self.analyze_audio(attachment)
                
                if audio_analysis:
                    audio_results["count"] += 1
                    audio_results["audio_files"].append(audio_analysis)
                    
                    # Update risk summary
                    audio_results["risk_summary"][audio_analysis["risk"]] += 1
            
            # Determine overall risk
            audio_results["overall_risk"] = self.determine_overall_risk(audio_results["risk_summary"])
            
            return audio_results
        
        except Exception as e:
            logger.exception("Error analyzing audio files")
            return {
                "count": 0,
                "audio_files": [],
                "risk_summary": {"safe": 0, "suspicious": 0, "malicious": 0},
                "overall_risk": "unknown",
                "error": str(e)
            }
    
    def is_audio(self, attachment):
        """Check if an attachment is an audio file"""
        content_type = attachment.get("content_type", "")
        filename = attachment.get("filename", "")
        
        # Check content type
        if content_type.startswith("audio/"):
            return True
        
        # Check filename extension
        audio_extensions = [".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac"]
        return any(filename.lower().endswith(ext) for ext in audio_extensions)
    
    def analyze_audio(self, attachment):
        """Analyze audio file for potential threats"""
        # In a real implementation, this would use speech recognition APIs
        # For this demo, we'll simulate audio transcription and analysis
        
        filename = attachment.get("filename", "unknown")
        size = attachment.get("size", 0)
        
        # Create audio analysis result
        audio_analysis = {
            "filename": filename,
            "size": size,
            "duration": self.estimate_duration(size),  # Estimate duration based on size
            "transcription": self.simulate_transcription(),
            "keywords": [],
            "risk": "safe",
            "details": ""
        }
        
        # Extract keywords from transcription
        audio_analysis["keywords"] = self.extract_keywords(audio_analysis["transcription"])
        
        # Determine risk level based on keywords
        self.determine_risk(audio_analysis)
        
        return audio_analysis
    
    def estimate_duration(self, size):
        """Estimate audio duration based on file size"""
        # Rough estimate: ~10KB per second for typical audio
        # This will vary based on bitrate, compression, etc.
        seconds = size / 10240
        
        # Format as MM:SS
        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)
        
        return f"{minutes}:{remaining_seconds:02d}"
    
    def simulate_transcription(self):
        """Simulate audio transcription for demo purposes"""
        # Sample transcriptions with different risk levels
        transcriptions = [
            # Safe transcriptions
            "Hello, this is a reminder about our meeting tomorrow at 2 PM. Please bring your presentation materials.",
            "Thank you for your recent purchase. Your order has been shipped and should arrive within 3-5 business days.",
            "This is an automated message from your calendar app. You have an appointment scheduled for next Tuesday.",
            
            # Suspicious transcriptions
            "This is an important message regarding your account. Please verify your information by visiting our secure website.",
            "Your bank account has been flagged for suspicious activity. Please call our security department immediately at the following number.",
            "This is tech support calling about your computer. We've detected a virus and need your immediate assistance to remove it.",
            
            # Malicious transcriptions
            "This is the IRS calling. You have unpaid taxes and a warrant has been issued for your arrest. To resolve this, please purchase gift cards and call us back with the codes.",
            "Your Social Security number has been suspended due to suspicious activity. To reactivate it, press 1 and provide your personal information to our agent.",
            "This is Microsoft support. Your computer is sending virus signals. We need your password and remote access to fix this urgent security issue."
        ]
        
        # Weighted selection to favor suspicious content for demo
        weights = [0.3, 0.4, 0.3]  # Safe, Suspicious, Malicious
        category = random.choices([0, 1, 2], weights=weights)[0]
        
        # Select a transcription from the appropriate category
        if category == 0:  # Safe
            return random.choice(transcriptions[0:3])
        elif category == 1:  # Suspicious
            return random.choice(transcriptions[3:6])
        else:  # Malicious
            return random.choice(transcriptions[6:9])
    
    def extract_keywords(self, transcription):
        """Extract potentially suspicious keywords from transcription"""
        # Lists of keywords with different risk levels to reduce false positives
        
        # High-risk keywords that strongly indicate malicious intent
        high_risk_keywords = [
            "social security number", "SSN", "gift card", "wire money", "Western Union", 
            "Bitcoin", "warrant for arrest", "law enforcement", "IRS calling", 
            "suspended SSN", "Microsoft support", "remote access", "computer virus", 
            "tech support calling", "iTunes gift card", "pay immediately", 
            "give me your password", "provide verification code"
        ]
        
        # Medium-risk keywords that may indicate suspicious content but need context
        medium_risk_keywords = [
            "urgent action required", "account suspended", "unusual activity",
            "tax problem", "legal action", "call this number immediately", 
            "security breach", "credit card suspended", "verify identity",
            "lawsuit pending", "payment problem", "overdue payment", 
            "compromised account", "confirm personal details"
        ]
        
        # Low-risk keywords common in legitimate business communications
        # (These should not trigger suspicion on their own)
        legitimate_keywords = [
            "account", "verify", "security", "bank", "credit card", "statement",
            "password", "login", "tax", "payment", "invoice", "transaction",
            "immediately", "problem", "issue", "suspend", "personal information",
            "customer service", "confirmation", "receipt", "notification"
        ]
        
        # Find keywords in transcription with categorization to reduce false positives
        transcript_lower = transcription.lower()
        found_keywords = {
            "high_risk": [],
            "medium_risk": [],
            "legitimate": []
        }
        
        # Note: We've replaced the single suspicious_keywords list with three categorized lists above
        
        # Check for high-risk keywords (strong indicators of malicious content)
        for keyword in high_risk_keywords:
            if keyword.lower() in transcript_lower:
                found_keywords["high_risk"].append(keyword)
        
        # Check for medium-risk keywords (potentially suspicious but need context)
        for keyword in medium_risk_keywords:
            if keyword.lower() in transcript_lower:
                found_keywords["medium_risk"].append(keyword)
        
        # Also track legitimate business keywords to help reduce false positives
        for keyword in legitimate_keywords:
            if keyword.lower() in transcript_lower:
                found_keywords["legitimate"].append(keyword)
        
        return found_keywords
    
    def determine_risk(self, audio_analysis):
        """Determine risk level based on keywords and content"""
        keywords = audio_analysis["keywords"]
        transcription = audio_analysis["transcription"].lower()
        
        # Count of different types of keywords
        high_risk_count = len(keywords.get("high_risk", []))
        medium_risk_count = len(keywords.get("medium_risk", []))
        legitimate_count = len(keywords.get("legitimate", []))
        
        # Define high-risk phrases that are more specific than just keyword combinations
        high_risk_phrases = [
            "purchase gift card",
            "wire money immediately", 
            "social security suspended",
            "irs calling about taxes",
            "warrant for your arrest", 
            "microsoft tech support",
            "access to your computer",
            "detected a virus",
            "provide password for verification"
        ]
        
        # Check for specific high-risk phrases (more accurate than just keyword pairs)
        for phrase in high_risk_phrases:
            if phrase in transcription:
                audio_analysis["risk"] = "malicious"
                audio_analysis["details"] = "Audio contains specific language used in known voice phishing scams"
                return
                
        # Check for high-risk keywords
        if high_risk_count >= 1:
            # Additional check to reduce false positives
            if high_risk_count > legitimate_count:
                audio_analysis["risk"] = "malicious"
                audio_analysis["details"] = f"Audio contains {high_risk_count} high-risk keywords commonly used in voice phishing"
                return
            else:
                # More legitimate terms than high-risk ones - could be a false positive
                audio_analysis["risk"] = "suspicious"
                audio_analysis["details"] = "Audio contains concerning keywords, but may be legitimate"
                return
        
        # Check for medium-risk keywords
        if medium_risk_count >= 2:
            # More sophisticated analysis to reduce false positives
            if medium_risk_count > (legitimate_count / 2):
                audio_analysis["risk"] = "suspicious"
                audio_analysis["details"] = "Audio contains multiple concerning patterns requiring caution"
                return
            else:
                # Likely a legitimate communication
                audio_analysis["risk"] = "safe"
                audio_analysis["details"] = "Audio mentions security terms but appears to be legitimate"
                return
                
        # Default case - safe
        audio_analysis["risk"] = "safe"
        audio_analysis["details"] = "No concerning patterns detected in audio content"
    
    def determine_overall_risk(self, risk_summary):
        """Determine overall risk level based on audio analysis results"""
        if risk_summary["malicious"] > 0:
            return "high"
        elif risk_summary["suspicious"] > 0:
            return "medium"
        elif risk_summary["safe"] > 0:
            return "low"
        else:
            return "unknown"
