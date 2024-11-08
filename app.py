import streamlit as st
import pandas as pd
import dns.resolver
import smtplib
from email_validator import validate_email, EmailNotValidError

# Set page title
st.title("Email Verification App")

# Function to validate email syntax
def is_valid_syntax(email):
    try:
        # Validate and get normalized email
        valid = validate_email(email)
        email = valid.email
        return True
    except EmailNotValidError as e:
        return False

# MX records cache
mx_cache = {}

# Function to get MX records
def get_mx_records(domain):
    if domain in mx_cache:
        return mx_cache[domain]
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(r.exchange).rstrip('.') for r in answers]
        mx_cache[domain] = mx_records
        return mx_records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        mx_cache[domain] = None
        return None
    except Exception:
        mx_cache[domain] = None
        return None

# Function to check SMTP
def check_smtp(email, mx_records):
    from_address = 'verify@mydomain.com'
    mx_record = mx_records[0]
    try:
        # Establish an SMTP connection
        server = smtplib.SMTP(mx_record, 25, timeout=10)
        server.ehlo_or_helo_if_needed()

        # Start TLS if supported
        try:
            server.starttls()
            server.ehlo()
        except smtplib.SMTPException:
            pass  # TLS may not be supported

        # SMTP conversation
        server.mail(from_address)
        code, message = server.rcpt(email)
        server.quit()

        # 250 means the email address is valid
        if code in [250, 251, 252]:
            return True
        else:
            return False
    except Exception as e:
        return False

# Sidebar options
st.sidebar.title("Options")
option = st.sidebar.selectbox("Choose an option:", ("Verify Single Email", "Verify Emails from CSV"))

# Verify Single Email
if option == "Verify Single Email":
    st.subheader("Verify a Single Email Address")
    single_email = st.text_input("Enter the email address:")
    if st.button("Verify Email"):
        if single_email:
            email_status = 'INVALID'

            # Step 1: Syntax Check
            if is_valid_syntax(single_email):
                # Step 2: Domain and MX Record Check
                domain = single_email.split('@')[1]
                mx_records = get_mx_records(domain)
                if mx_records:
                    # Step 3: SMTP Check
                    if check_smtp(single_email, mx_records):
                        email_status = 'VALID'

            # Display the result
            st.write(f"The email address **{single_email}** is **{email_status}**.")
        else:
            st.error("Please enter an email address.")

# Verify Emails from CSV
elif option == "Verify Emails from CSV":
    st.subheader("Verify Emails from a CSV File")

    # File uploader
    uploaded_file = st.file_uploader("Upload a CSV file with an 'email' column", type=["csv"])

    # Main processing
    if uploaded_file is not None:
        try:
            # Read the CSV file
            df = pd.read_csv(uploaded_file)

            # Check if 'email' column exists
            if 'email' not in df.columns:
                st.error("The uploaded CSV file does not contain an 'email' column.")
            else:
                # Prepare the DataFrame
                df['status'] = 'Pending'

                # Display initial DataFrame
                result_placeholder = st.empty()
                result_placeholder.write(df)

                # Progress bar
                progress_bar = st.progress(0)

                # Iterate over each email
                total_emails = len(df)
                for index, row in df.iterrows():
                    email = row['email']
                    email_status = 'INVALID'

                    # Step 1: Syntax Check
                    if is_valid_syntax(email):
                        # Step 2: Domain and MX Record Check
                        domain = email.split('@')[1]
                        mx_records = get_mx_records(domain)
                        if mx_records:
                            # Step 3: SMTP Check
                            if check_smtp(email, mx_records):
                                email_status = 'VALID'

                    # Update the status in DataFrame
                    df.at[index, 'status'] = email_status

                    # Update progress bar
                    progress = (index + 1) / total_emails
                    progress_bar.progress(progress)

                    # Update the displayed DataFrame
                    result_placeholder.write(df)

                # Display completion message
                st.success("Email verification completed.")

                # Download button for the result CSV
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download Results as CSV",
                    data=csv,
                    file_name='email_verification_results.csv',
                    mime='text/csv',
                )
        except Exception as e:
            st.error(f"An error occurred: {e}")
