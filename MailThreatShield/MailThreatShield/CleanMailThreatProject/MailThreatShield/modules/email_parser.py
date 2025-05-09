import email
import logging
import re
import os
from email import policy
from email.parser import BytesParser, Parser

logger = logging.getLogger(__name__)

class EmailParser:
    """Parses email content and extracts relevant information"""
    
    def __init__(self, email_content):
        self.email_content = email_content
        
    def parse(self):
        """Parse the email content and return structured data"""
        try:
            # Determine if the content is bytes or string
            if isinstance(self.email_content, bytes):
                parser = BytesParser(policy=policy.default)
                parsed_email = parser.parsebytes(self.email_content)
            else:
                parser = Parser(policy=policy.default)
                parsed_email = parser.parsestr(self.email_content)
            
            # Extract basic email information
            email_data = {
                "subject": parsed_email.get("Subject", "No Subject"),
                "from": parsed_email.get("From", "unknown@sender.com"),
                "to": parsed_email.get("To", "unknown@recipient.com"),
                "date": parsed_email.get("Date", "Unknown Date"),
                "headers": dict(parsed_email.items()),
                "body_plain": "",
                "body_html": "",
                "attachments": [],
                "urls": []
            }
            
            # Extract IP addresses from headers
            received_headers = parsed_email.get_all("Received", [])
            email_data["ip_addresses"] = self.extract_ip_addresses(received_headers)
            
            # Extract Return-Path header
            email_data["return_path"] = parsed_email.get("Return-Path", "")
            
            # Extract authentication results
            email_data["auth_results"] = parsed_email.get("Authentication-Results", "")
            
            # Process body parts
            has_valid_body = False
            
            for part in parsed_email.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Handle attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        try:
                            payload = part.get_payload(decode=True)
                            attachment_data = {
                                "filename": filename,
                                "content_type": content_type,
                                "size": len(payload or b''),
                                "content": payload
                            }
                            email_data["attachments"].append(attachment_data)
                        except Exception as e:
                            logger.error(f"Error processing attachment: {e}")
                
                # Handle body content
                elif content_type == "text/plain" and part.get_payload(decode=True):
                    try:
                        payload_bytes = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        if payload_bytes and isinstance(payload_bytes, bytes):
                            email_data["body_plain"] = payload_bytes.decode(charset, errors='replace')
                            has_valid_body = True
                    except Exception as e:
                        logger.error(f"Error decoding plain text body: {e}")
                
                elif content_type == "text/html" and part.get_payload(decode=True):
                    try:
                        payload_bytes = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        if payload_bytes and isinstance(payload_bytes, bytes):
                            email_data["body_html"] = payload_bytes.decode(charset, errors='replace')
                            has_valid_body = True
                    except Exception as e:
                        logger.error(f"Error decoding HTML body: {e}")

            # If we couldn't parse body properly, try the full payload as a fallback
            if not has_valid_body and parsed_email.get_payload():
                if isinstance(parsed_email.get_payload(), list):
                    # Multipart message - get the first text part
                    for subpart in parsed_email.get_payload():
                        try:
                            if hasattr(subpart, "get_content_type") and subpart.get_content_type() in ['text/plain', 'text/html']:
                                try:
                                    charset = subpart.get_content_charset() or 'utf-8'
                                    content = subpart.get_payload(decode=True)
                                    if content and isinstance(content, bytes):
                                        if subpart.get_content_type() == 'text/plain':
                                            email_data["body_plain"] = content.decode(charset, errors='replace')
                                        else:
                                            email_data["body_html"] = content.decode(charset, errors='replace')
                                        has_valid_body = True
                                        break
                                except Exception as e:
                                    logger.error(f"Error in fallback body parsing: {e}")
                        except Exception as e:
                            logger.error(f"Error accessing subpart properties: {e}")
                            continue
                else:
                    # Single part message
                    try:
                        content = parsed_email.get_payload(decode=True)
                        if content and isinstance(content, bytes):
                            if hasattr(parsed_email, "get_content_type") and 'html' in parsed_email.get_content_type():
                                email_data["body_html"] = content.decode('utf-8', errors='replace')
                            else:
                                email_data["body_plain"] = content.decode('utf-8', errors='replace')
                            has_valid_body = True
                    except Exception as e:
                        logger.error(f"Error in single part fallback: {e}")
                        
            # Last resort: If still no valid body, try to extract directly from raw content
            if not has_valid_body and isinstance(self.email_content, str):
                html_pattern = r'<!DOCTYPE html.*?>(.*?)</html>'
                html_match = re.search(html_pattern, self.email_content, re.DOTALL | re.IGNORECASE)
                if html_match:
                    email_data["body_html"] = html_match.group(0)
                    has_valid_body = True
            
            # Extract URLs from body content with improved pattern matching
            combined_content = email_data["body_plain"] + email_data["body_html"]
            email_data["urls"] = self.extract_urls(combined_content)
            
            logger.info(f"Email parsed successfully: {email_data['subject']}")
            logger.info(f"Found {len(email_data['urls'])} URLs and {len(email_data['attachments'])} attachments")
            
            return email_data
        
        except Exception as e:
            logger.exception(f"Error parsing email content: {str(e)}")
            # Return a minimal response on failure
            return {
                "subject": "Error parsing email",
                "from": "unknown@sender.com",
                "to": "unknown@recipient.com",
                "date": "Unknown Date",
                "headers": {},
                "body_plain": "",
                "body_html": "",
                "attachments": [],
                "urls": [],
                "error": str(e)
            }
    
    def extract_ip_addresses(self, headers):
        """Extract IP addresses from Received headers"""
        ips = []
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for header in headers:
            found_ips = re.findall(ip_pattern, header)
            ips.extend(found_ips)
        
        return list(set(ips))  # Return unique IPs
    
    def extract_urls(self, text):
        """Extract URLs from text content with improved pattern matching"""
        # More comprehensive pattern to catch URLs in HTML and plain text
        url_pattern = r'(?:https?:\/\/|www\.)[^\s\'"<>()]+|href=["\'](https?:\/\/[^\s\'"<>]+|www\.[^\s\'"<>]+)["\']|(?:https?:\/\/|www\.)[^\s\'"<>]+'
        
        urls = re.findall(url_pattern, text)
        
        # Clean up URLs
        cleaned_urls = []
        for url in urls:
            if isinstance(url, tuple):
                # Handle tuple results from regex groups
                url = next((u for u in url if u), "")
                
            if url.startswith('href='):
                url = url[6:-1]  # Remove href=' and trailing '
            elif url.startswith('"') and url.endswith('"'):
                url = url[1:-1]  # Remove quotes
                
            # Ensure URL has protocol
            if url.startswith('www.'):
                url = 'http://' + url
                
            # Filter out common false positives
            if url and len(url) > 4 and '.' in url and not url.endswith('.'):
                cleaned_urls.append(url)
        
        # Remove duplicates while preserving order
        unique_urls = []
        for url in cleaned_urls:
            if url not in unique_urls:
                unique_urls.append(url)
                
        return unique_urls
