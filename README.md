# Gmail Unsubscribe Filter Setup Instructions

## Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

## Step 2: Set up Gmail API Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Gmail API:
   - Go to "APIs & Services" > "Library"
   - Search for "Gmail API"
   - Click on it and press "Enable"

4. Create credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Desktop application"
   - Give it a name (e.g., "Gmail Unsubscribe Filter")
   - Download the JSON file

5. Rename the downloaded file to `credentials.json` and place it in the same folder as this script

## Step 3: Run the Script
```bash
python gmail_unsubscribe_filter.py
```

The first time you run it, it will open a browser window for you to authorize access to your Gmail account.

## What the Script Does

1. **Connects to your Gmail** using the Gmail API
2. **Searches for emails** containing unsubscribe-related keywords
3. **Filters out automated emails** from companies, newsletters, etc.
4. **Identifies real people** who want to unsubscribe based on:
   - Email domain (personal domains like gmail.com, yahoo.com)
   - Email format (looks like a person's name)
   - Sender name patterns
5. **Saves results** in multiple formats:
   - `unsubscribe_requests.json` - Detailed information
   - `unsubscribe_emails.txt` - Just the email addresses
   - `unsubscribe_requests.csv` - Spreadsheet format

## Output Files

After running, you'll get three files:
- **unsubscribe_emails.txt** - Simple list of email addresses
- **unsubscribe_requests.csv** - Can be opened in Excel
- **unsubscribe_requests.json** - Full details including subject, date, etc.

## Security Notes

- Your credentials are stored locally in `credentials.json` and `token.pickle`
- The script only reads your emails (no sending or deleting)
- Your email data stays on your computer
