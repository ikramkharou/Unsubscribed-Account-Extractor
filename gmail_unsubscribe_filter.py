#!/usr/bin/env python3
"""
Gmail Unsubscribe Filter Script
This script connects to Gmail and filters emails to find people who want to unsubscribe.
"""

import os
import re
import pickle
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import json

# Gmail API scope
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

class GmailUnsubscribeFilter:
    def __init__(self):
        self.service = None
        self.unsubscribe_keywords = [
            'unsubscribe', 'remove me', 'stop emails', 'opt out', 'no longer interested',
            'cancel subscription', 'remove from list', 'stop sending', 'delete my email',
            'unsubscribe me', 'take me off', 'stop mailings', 'remove my email'
        ]
        
        # Keywords that suggest automated/company emails (to ignore)
        self.company_indicators = [
            'noreply', 'no-reply', 'donotreply', 'automated', 'system',
            'newsletter', 'marketing', 'promo', 'notification', 'alert',
            'support@', 'admin@', 'info@', 'sales@', 'help@',
            'mailer-daemon', 'postmaster', 'newsletter@', 'updates@',
            'shopify', 'mailer@', 'notifications@', 'team@', 'hello@',
            'contact@', 'service@', 'update@', 'news@', 'account@',
            'security@', 'billing@', 'orders@', 'shipping@'
        ]
        
        # Company domains to ignore
        self.company_domains = [
            'shopify.com', 'apple.com', 'icloud.com', 'microsoft.com',
            'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'linkedin.com', 'amazon.com', 'paypal.com', 'stripe.com',
            'mailchimp.com', 'constantcontact.com', 'aweber.com',
            'sendgrid.com', 'mailgun.com', 'mandrill.com'
        ]
    
    def authenticate(self):
        """Authenticate with Gmail API"""
        creds = None
        # Check if token.pickle exists
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        # If there are no (valid) credentials available, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists('credentials.json'):
                    print("ERROR: credentials.json file not found!")
                    print("Please download your Gmail API credentials from Google Cloud Console")
                    print("and save them as 'credentials.json' in this directory.")
                    return False
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        try:
            self.service = build('gmail', 'v1', credentials=creds)
            print("✅ Successfully authenticated with Gmail API")
            return True
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False
    
    def is_likely_person(self, sender_email, sender_name=""):
        """Check if the sender is likely a real person (not automated/company)"""
        sender_email = sender_email.lower()
        sender_name = sender_name.lower()
        
        # Check for company indicators in email
        for indicator in self.company_indicators:
            if indicator in sender_email or indicator in sender_name:
                return False
        
        # Check if domain is a known company domain
        domain = sender_email.split('@')[-1] if '@' in sender_email else ""
        if domain in self.company_domains:
            return False
        
        # Additional company domain patterns to ignore
        company_domain_patterns = [1
            '.shopify.com', 'mailer.', 'mail.', 'email.', 'smtp.',
            'newsletter.', 'marketing.', 'promo.', 'notification.'
        ]
        
        for pattern in company_domain_patterns:
            if pattern in domain:
                return False
        
        # Check for common personal email domains
        personal_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                          'aol.com', 'live.com', 'msn.com', 'ymail.com', 'protonmail.com']
        
        # ISP domains (likely personal)
        isp_domains = [
            'roadrunner.com', 'rr.com', 'charter.net', 'comcast.net', 
            'verizon.net', 'att.net', 'bellsouth.net', 'cox.net',
            'twc.com', 'twcny.rr.com', 'maine.rr.com', 'nyc.rr.com',
            'nycap.rr.com', 'nc.rr.com', 'wi.rr.com', 'oh.rr.com',
            'rochester.rr.com', 'tampabay.rr.com', 'triad.rr.com',
            'austin.rr.com', 'neb.rr.com', 'sc.rr.com'
        ]
        
        # If it's a personal or ISP domain, likely to be a person
        if domain in personal_domains or domain in isp_domains:
            # But still check if it looks like an automated email
            local_part = sender_email.split('@')[0] if '@' in sender_email else sender_email
            
            # Automated email patterns to reject even on personal domains
            automated_patterns = [
                'noreply', 'no-reply', 'donotreply', 'mailer', 'automated',
                'system', 'admin', 'support', 'help', 'service', 'team',
                'info', 'contact', 'sales', 'marketing', 'newsletter'
            ]
            
            for pattern in automated_patterns:
                if pattern in local_part:
                    return False
            
            return True
        
        # For other domains, check if email looks like a person's name
        local_part = sender_email.split('@')[0] if '@' in sender_email else sender_email
        
        # Common personal email patterns
        personal_patterns = [
            r'^[a-z]+\.[a-z]+\d*$',  # firstname.lastname123
            r'^[a-z]+[a-z0-9]*$',    # firstname123  
            r'^[a-z]\.[a-z]+$',      # j.smith
            r'^[a-z]+_[a-z]+\d*$',   # firstname_lastname123
        ]
        
        for pattern in personal_patterns:
            if re.match(pattern, local_part):
                return True
        
        return False
    
    def contains_unsubscribe_request(self, email_content):
        """Check if email content contains unsubscribe request"""
        content_lower = email_content.lower()
        
        for keyword in self.unsubscribe_keywords:
            if keyword in content_lower:
                return True
        
        return False
    
    def get_email_content(self, message_id):
        """Get the content of an email message"""
        try:
            message = self.service.users().messages().get(
                userId='me', id=message_id, format='full').execute()
            
            payload = message['payload']
            body = ""
            
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        if 'data' in part['body']:
                            body = base64.urlsafe_b64decode(
                                part['body']['data']).decode('utf-8')
                            break
            else:
                if payload['mimeType'] == 'text/plain':
                    if 'data' in payload['body']:
                        body = base64.urlsafe_b64decode(
                            payload['body']['data']).decode('utf-8')
            
            return body
        except Exception as e:
            print(f"Error getting email content: {e}")
            return ""
    
    def extract_sender_info(self, headers):
        """Extract sender email and name from headers"""
        sender_email = ""
        sender_name = ""
        
        for header in headers:
            if header['name'] == 'From':
                from_field = header['value']
                # Parse "Name <email@domain.com>" format
                match = re.match(r'^(.*?)\s*<(.+?)>$', from_field)
                if match:
                    sender_name = match.group(1).strip().strip('"')
                    sender_email = match.group(2).strip()
                else:
                    sender_email = from_field.strip()
                break
        
        return sender_email, sender_name
    
    def get_all_emails(self):
        """Get ALL emails from the account (no limits)"""
        try:
            # Search query - get ALL emails (no date restriction)
            query = ''  # Empty query gets all emails
            
            print(f"📧 Getting ALL emails from your account...")
            print(f"   No limits - will get every email in your account")
            
            all_messages = []
            page_token = None
            
            while True:
                if page_token:
                    results = self.service.users().messages().list(
                        userId='me', q=query, maxResults=500, 
                        pageToken=page_token).execute()
                else:
                    results = self.service.users().messages().list(
                        userId='me', q=query, maxResults=500).execute()
                
                messages = results.get('messages', [])
                if not messages:
                    break
                
                all_messages.extend(messages)
                print(f"   Retrieved {len(all_messages)} emails so far...")
                
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            
            print(f"✅ Retrieved {len(all_messages)} total emails")
            return all_messages
        
        except HttpError as error:
            print(f'An error occurred getting emails: {error}')
            return []
    
    def analyze_and_filter_emails(self, all_messages):
        """Analyze ALL emails and filter for unsubscribe requests from real people"""
        print(f"\n🔍 Analyzing {len(all_messages)} emails for unsubscribe requests...")
        
        unsubscribe_requests = []
        all_analyzed_emails = []
        
        for i, message in enumerate(all_messages):
            try:
                # Get message details
                msg = self.service.users().messages().get(
                    userId='me', id=message['id'], format='metadata').execute()
                
                headers = msg['payload']['headers']
                sender_email, sender_name = self.extract_sender_info(headers)
                
                # Get subject
                subject = ""
                for header in headers:
                    if header['name'] == 'Subject':
                        subject = header['value']
                        break
                
                # Get date
                date = ""
                for header in headers:
                    if header['name'] == 'Date':
                        date = header['value']
                        break
                
                # Store basic email info
                email_info = {
                    'email': sender_email,
                    'name': sender_name,
                    'subject': subject,
                    'date': date,
                    'message_id': message['id'],
                    'is_person': self.is_likely_person(sender_email, sender_name),
                    'has_unsubscribe': False,
                    'content_preview': ''
                }
                
                # Get email content for analysis (with error handling)
                try:
                    content = self.get_email_content(message['id'])
                    if content:
                        email_info['content_preview'] = content[:200] + '...' if len(content) > 200 else content
                        email_info['has_unsubscribe'] = self.contains_unsubscribe_request(content)
                except Exception as e:
                    print(f"   Warning: Could not read content for email {i+1}: {e}")
                    # Check subject for unsubscribe keywords as fallback
                    email_info['has_unsubscribe'] = self.contains_unsubscribe_request(subject)
                    email_info['content_preview'] = f"[Could not read content - checked subject: {subject[:100]}]"
                
                all_analyzed_emails.append(email_info)
                
                # Check if this is an unsubscribe request from a real person
                if email_info['is_person'] and email_info['has_unsubscribe']:
                    unsubscribe_requests.append(email_info)
                    print(f"✅ Found unsubscribe request from: {sender_email}")
                
                # Progress indicator and save intermediate results
                if (i + 1) % 50 == 0:
                    print(f"   Analyzed {i + 1}/{len(all_messages)} emails...")
                    print(f"   Found {len(unsubscribe_requests)} unsubscribe requests so far")
                    
                    # Save intermediate results every 100 emails
                    if (i + 1) % 100 == 0:
                        self.save_intermediate_results(unsubscribe_requests, i + 1)
            
            except Exception as e:
                print(f"Error analyzing message {i+1}: {e}")
                continue
        
        # Save all analyzed emails for reference
        self.save_all_emails_analysis(all_analyzed_emails)
        
        return unsubscribe_requests
    
    def save_intermediate_results(self, unsubscribe_requests, processed_count):
        """Save intermediate results to avoid losing progress"""
        if unsubscribe_requests:
            # Save just email addresses to intermediate file
            with open(f'intermediate_unsubscribe_emails_{processed_count}.txt', 'w', encoding='utf-8') as f:
                for request in unsubscribe_requests:
                    f.write(f"{request['email']}\n")
            print(f"   💾 Saved intermediate results ({len(unsubscribe_requests)} emails) to intermediate_unsubscribe_emails_{processed_count}.txt")
    
    def save_all_emails_analysis(self, all_analyzed_emails):
        """Save complete analysis of all emails"""
        print(f"\n💾 Saving analysis of {len(all_analyzed_emails)} emails...")
        
        # Save detailed analysis to JSON
        with open('all_emails_analysis.json', 'w', encoding='utf-8') as f:
            json.dump(all_analyzed_emails, f, indent=2, ensure_ascii=False)
        
        # Create summary statistics
        total_emails = len(all_analyzed_emails)
        person_emails = sum(1 for email in all_analyzed_emails if email['is_person'])
        company_emails = total_emails - person_emails
        emails_with_unsubscribe = sum(1 for email in all_analyzed_emails if email['has_unsubscribe'])
        
        summary = {
            'analysis_date': datetime.now().isoformat(),
            'total_emails_analyzed': total_emails,
            'emails_from_people': person_emails,
            'emails_from_companies': company_emails,
            'emails_with_unsubscribe_keywords': emails_with_unsubscribe,
            'unsubscribe_requests_from_people': sum(1 for email in all_analyzed_emails 
                                                   if email['is_person'] and email['has_unsubscribe'])
        }
        
        with open('email_analysis_summary.json', 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        # Save list of all unique senders
        unique_senders = {}
        for email in all_analyzed_emails:
            sender = email['email']
            if sender not in unique_senders:
                unique_senders[sender] = {
                    'name': email['name'],
                    'is_person': email['is_person'],
                    'email_count': 1,
                    'has_unsubscribe_requests': email['has_unsubscribe']
                }
            else:
                unique_senders[sender]['email_count'] += 1
                if email['has_unsubscribe']:
                    unique_senders[sender]['has_unsubscribe_requests'] = True
        
        with open('unique_senders.json', 'w', encoding='utf-8') as f:
            json.dump(unique_senders, f, indent=2, ensure_ascii=False)
        
        print(f"📊 Analysis Summary:")
        print(f"   Total emails analyzed: {total_emails}")
        print(f"   Emails from people: {person_emails}")
        print(f"   Emails from companies: {company_emails}")
        print(f"   Emails with unsubscribe keywords: {emails_with_unsubscribe}")
        print(f"   Unique senders: {len(unique_senders)}")
    
    def save_results(self, unsubscribe_requests):
        """Save the results to files"""
        if not unsubscribe_requests:
            print("No unsubscribe requests found from real people.")
            return
        
        # Save detailed results to JSON
        with open('unsubscribe_requests.json', 'w', encoding='utf-8') as f:
            json.dump(unsubscribe_requests, f, indent=2, ensure_ascii=False)
        
        # Save just email addresses to text file
        with open('unsubscribe_emails.txt', 'w', encoding='utf-8') as f:
            for request in unsubscribe_requests:
                f.write(f"{request['email']}\n")
        
        # Save CSV format
        with open('unsubscribe_requests.csv', 'w', encoding='utf-8') as f:
            f.write('Email,Name,Subject,Date\n')
            for request in unsubscribe_requests:
                name = request['name'].replace(',', ';') if request['name'] else ''
                subject = request['subject'].replace(',', ';') if request['subject'] else ''
                f.write(f"{request['email']},{name},{subject},{request['date']}\n")
        
        print(f"\n📊 Results Summary:")
        print(f"   Found {len(unsubscribe_requests)} unsubscribe requests from real people")
        print(f"   Results saved to:")
        print(f"   - unsubscribe_requests.json (detailed)")
        print(f"   - unsubscribe_emails.txt (email list)")
        print(f"   - unsubscribe_requests.csv (spreadsheet format)")

def main():
    """Main function"""
    print("🚀 Gmail Unsubscribe Filter Tool")
    print("=" * 50)
    
    filter_tool = GmailUnsubscribeFilter()
    
    # Authenticate
    if not filter_tool.authenticate():
        return
    
    print(f"\n📋 Analysis Plan:")
    print(f"   1. Get ALL emails from your account (no limits)")
    print(f"   2. Analyze content of each email")
    print(f"   3. Filter for people who want to unsubscribe")
    print(f"   4. Generate detailed reports")
    print(f"\n🚀 Starting analysis...")
    
    # Step 1: Get ALL emails
    all_messages = filter_tool.get_all_emails()
    
    if not all_messages:
        print("No emails found in your account.")
        return
    
    # Step 2 & 3: Analyze and filter emails
    unsubscribe_requests = filter_tool.analyze_and_filter_emails(all_messages)
    
    # Step 4: Save results
    filter_tool.save_results(unsubscribe_requests)
    
    print("\n✨ Analysis Complete!")
    print("📁 Generated files:")
    print("   - all_emails_analysis.json (complete analysis)")
    print("   - email_analysis_summary.json (statistics)")
    print("   - unique_senders.json (sender analysis)")
    print("   - unsubscribe_requests.json (filtered results)")
    print("   - unsubscribe_emails.txt (email list)")
    print("   - unsubscribe_requests.csv (spreadsheet format)")

if __name__ == "__main__":
    main()
