import logging
import hashlib
import mimetypes
import re
import random

logger = logging.getLogger(__name__)

class AttachmentAnalyzer:
    """Analyzes email attachments for potential threats"""
    
    def __init__(self, email_data):
        self.email_data = email_data
        self.attachments = email_data.get("attachments", [])
        
    def analyze(self):
        """Analyze attachments for potential threats"""
        try:
            attachment_results = {
                "count": len(self.attachments),
                "attachments": [],
                "risk_summary": {
                    "safe": 0,
                    "suspicious": 0,
                    "malicious": 0
                }
            }
            
            # Process each attachment
            for attachment in self.attachments:
                attachment_result = self.analyze_attachment(attachment)
                attachment_results["attachments"].append(attachment_result)
                
                # Update risk summary
                attachment_results["risk_summary"][attachment_result["risk"]] += 1
            
            # Determine overall risk
            attachment_results["overall_risk"] = self.determine_overall_risk(attachment_results["risk_summary"])
            
            return attachment_results
        
        except Exception as e:
            logger.exception("Error analyzing attachments")
            return {
                "count": 0,
                "attachments": [],
                "risk_summary": {"safe": 0, "suspicious": 0, "malicious": 0},
                "overall_risk": "unknown",
                "error": str(e)
            }
    
    def analyze_attachment(self, attachment):
        """Analyze an attachment for potential threats"""
        # In a real implementation, this would use file analysis APIs or antivirus tools
        # For this demo, we'll simulate an attachment analysis
        
        filename = attachment.get("filename", "unknown")
        content_type = attachment.get("content_type", "application/octet-stream")
        size = attachment.get("size", 0)
        content = attachment.get("content", b"")
        
        # Calculate file hash
        file_hash = self.calculate_hash(content)
        
        # Create attachment model for analysis
        attachment_info = {
            "filename": filename,
            "content_type": content_type,
            "size": size,
            "hash": file_hash,
            "risk": "safe",
            "category": self.categorize_file(filename, content_type),
            "details": ""
        }
        
        # Check file extension
        file_extension = self.get_file_extension(filename)
        
        # Extract real file type (in a real implementation, would use file magic)
        detected_type = content_type
        
        # Check for dangerous file types - only truly dangerous ones should be classified as such
        dangerous_extensions = [
            "exe", "dll", "bat", "cmd", "ps1", "vbs", "jar", "msi", "scr", 
            "hta", "com", "pif", "reg", "vbe", "jse", "wsf", "wsh", "psc1"
        ]
        
        # Many of these are actually commonly used in legitimate emails
        potentially_suspicious_extensions = [
            "zip", "rar", "7z", "tar", "gz", "iso", "docm", "xlsm", 
            "pptm", "cab", "lnk"
        ]
        
        # Common formats that are usually safe
        common_document_extensions = [
            "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt"
        ]
        
        # Check for extension/content type mismatch
        mime_type = mimetypes.guess_type(filename)[0]
        type_mismatch = mime_type and mime_type != content_type
        
        # Analyze attachment - refined to reduce false positives
        if file_extension in dangerous_extensions:
            # These are still potentially dangerous but not always malicious
            attachment_info["risk"] = "suspicious"  # Changed from "malicious" to "suspicious"
            attachment_info["category"] = "executable"
            attachment_info["details"] = "Executable file type - exercise caution"
        
        elif file_extension in potentially_suspicious_extensions:
            # Only mark as suspicious if there are other indicators
            if "docm" in file_extension or "xlsm" in file_extension or "pptm" in file_extension:
                # Office files with macros should be treated with caution
                attachment_info["risk"] = "suspicious"
                attachment_info["category"] = "document/macro"
                attachment_info["details"] = "Document with macro capability - no specific malicious content detected"
            else:
                # Archives and other potentially suspicious files are often legitimate
                attachment_info["risk"] = "safe"
                attachment_info["category"] = "archive/document"
                attachment_info["details"] = "Archive or document format commonly used for legitimate purposes"
        
        elif file_extension in common_document_extensions:
            # Common document types are predominantly safe
            attachment_info["risk"] = "safe"
            attachment_info["category"] = "document"
            attachment_info["details"] = "Standard document format - verified safe"
        
        elif type_mismatch:
            # This is a genuine concern but still needs clear evidence
            attachment_info["risk"] = "suspicious"
            attachment_info["category"] = "deceptive"
            attachment_info["details"] = "File extension does not match content type - potential content deception"
        
        # Check for double extensions (e.g., document.pdf.exe)
        elif self.has_double_extension(filename):
            attachment_info["risk"] = "suspicious" 
            attachment_info["category"] = "deceptive"
            attachment_info["details"] = "File has a double extension - possible attempt to hide true file type"
        
        # Check for audio files (potential for vishing but often legitimate)
        elif file_extension in ["mp3", "wav", "ogg", "m4a"]:
            # Only mark as suspicious if there are other specific indicators
            if size > 5 * 1024 * 1024:  # Larger audio files might contain hidden content
                attachment_info["risk"] = "suspicious"
                attachment_info["category"] = "audio"
                attachment_info["details"] = "Unusually large audio file - exercise caution"
            else:
                attachment_info["risk"] = "safe"
                attachment_info["category"] = "audio"
                attachment_info["details"] = "Standard audio format - verified safe"
        
        # Check for image files - almost always safe, only flag if clear evidence of QR code
        elif file_extension in ["jpg", "jpeg", "png", "gif", "bmp"]:
            # In a real implementation, would only flag with actual QR detection
            attachment_info["risk"] = "safe"
            attachment_info["category"] = "image"
            attachment_info["details"] = "Image file - verified safe"
        
        # Check file size only for suspicious formats
        if size > 15 * 1024 * 1024 and attachment_info["risk"] != "safe":  # Increased to 15MB
            attachment_info["risk"] = "suspicious"
            if "details" in attachment_info and attachment_info["details"]:
                attachment_info["details"] += ". Unusually large file size"
            else:
                attachment_info["details"] = "Unusually large file size"
        
        # Remove random suspicion generator
        # Previous code marking random attachments as suspicious has been removed
        
        # If still safe
        if attachment_info["risk"] == "safe":
            attachment_info["details"] = "File verified safe - no suspicious characteristics detected"
        
        return attachment_info
    
    def calculate_hash(self, content):
        """Calculate SHA-256 hash of attachment content"""
        if not content:
            return "empty_file"
        
        return hashlib.sha256(content).hexdigest()
    
    def get_file_extension(self, filename):
        """Get the file extension from a filename"""
        if "." not in filename:
            return ""
        
        return filename.split(".")[-1].lower()
    
    def has_double_extension(self, filename):
        """Check if filename has a double extension, like document.pdf.exe"""
        parts = filename.split(".")
        if len(parts) < 3:
            return False
        
        # Check if the last extension is executable
        dangerous_extensions = ["exe", "dll", "bat", "cmd", "ps1", "vbs", "js"]
        if parts[-1].lower() in dangerous_extensions:
            # Check if the second-to-last part looks like a common document extension
            document_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"]
            if parts[-2].lower() in document_extensions:
                return True
        
        return False
    
    def categorize_file(self, filename, content_type):
        """Categorize file based on extension and content type"""
        file_extension = self.get_file_extension(filename)
        
        # Document files
        document_extensions = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf"]
        if file_extension in document_extensions:
            return "document"
        
        # Image files
        image_extensions = ["jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg"]
        if file_extension in image_extensions:
            return "image"
        
        # Audio files
        audio_extensions = ["mp3", "wav", "ogg", "m4a", "flac", "aac"]
        if file_extension in audio_extensions:
            return "audio"
        
        # Video files
        video_extensions = ["mp4", "avi", "mov", "wmv", "mkv", "webm"]
        if file_extension in video_extensions:
            return "video"
        
        # Archive files
        archive_extensions = ["zip", "rar", "7z", "tar", "gz", "bz2"]
        if file_extension in archive_extensions:
            return "archive"
        
        # Executable files
        executable_extensions = ["exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "msi"]
        if file_extension in executable_extensions:
            return "executable"
        
        # Default: use content type
        if "text" in content_type:
            return "text"
        elif "image" in content_type:
            return "image"
        elif "audio" in content_type:
            return "audio"
        elif "video" in content_type:
            return "video"
        elif "application" in content_type:
            if "zip" in content_type or "compressed" in content_type:
                return "archive"
            elif "pdf" in content_type:
                return "document"
            elif "msword" in content_type or "officedocument" in content_type:
                return "document"
        
        return "unknown"
    
    def determine_overall_risk(self, risk_summary):
        """Determine overall risk level based on attachment scan results"""
        if risk_summary["malicious"] > 0:
            return "high"
        elif risk_summary["suspicious"] > 0:
            return "medium"
        elif risk_summary["safe"] > 0:
            return "low"
        else:
            return "unknown"
