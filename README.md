# Email Verification App

A Streamlit-based web application that verifies email addresses through multiple validation steps, including syntax checking, domain verification, and SMTP validation.

## Features

- **Single Email Verification**: Verify individual email addresses in real-time
- **Bulk Email Verification**: Upload a CSV file containing multiple email addresses for batch verification
- **Multi-step Validation**:
  - Email syntax validation
  - Domain and MX record verification
  - SMTP server validation
- **Export Results**: Download verification results as a CSV file

## Prerequisites

Before running this application, make sure you have Python 3.6+ installed on your system. The following Python packages are required:

```bash
streamlit
pandas
dnspython
```

## Installation

1. Clone this repository:
```bash
git clone https://github.com/mohibmirza-py/email-verifier-script.git
cd email-verifier-script
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the Streamlit app:
```bash
streamlit run app.py
```

2. Open your web browser and navigate to the URL shown in your terminal (typically `http://localhost:8501`)

### Single Email Verification
1. Select "Verify Single Email" from the sidebar
2. Enter an email address in the input field
3. Click "Verify Email" to see the results

### Bulk Email Verification
1. Select "Verify Emails from CSV" from the sidebar
2. Prepare a CSV file with an 'email' column containing the email addresses to verify
3. Upload the CSV file
4. Wait for the verification process to complete
5. Download the results using the "Download Results as CSV" button

## CSV File Format

Your CSV file should have the following format:
```csv
email
user1@example.com
user2@example.com
user3@example.com
```

## Verification Status

The app returns two possible statuses:
- **VALID**: The email address passed all verification checks
- **INVALID**: The email address failed one or more verification checks

## Limitations

- Some email servers might block SMTP verification attempts
- Rate limiting may apply when verifying multiple email addresses
- The accuracy of SMTP verification can vary depending on the email server's configuration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for verification purposes only. Please ensure you comply with all applicable laws and regulations regarding email verification and spam prevention.