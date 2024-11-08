import streamlit as st
import pandas as pd
import dns.resolver
import smtplib
from email_validator import validate_email, EmailNotValidError
import openai
import os

from dotenv load_dotenv
load_dotenv()

# Function to validate email syntax
def is_valid_syntax(email):
    try:
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
        server = smtplib.SMTP(mx_record, 25, timeout=10)
        server.ehlo_or_helo_if_needed()
        try:
            server.starttls()
            server.ehlo()
        except smtplib.SMTPException:
            pass
        server.mail(from_address)
        code, message = server.rcpt(email)
        server.quit()
        return code in [250, 251, 252]
    except Exception as e:
        return False

# Function to handle email verification functionality
def verify_emails():
    verify_option = st.selectbox("Verify a Single Email or Upload CSV?", ("Single Email", "CSV File"))
    if verify_option == "Single Email":
        single_email = st.text_input("Enter the email address:")
        if st.button("Verify Email"):
            if single_email:
                email_status = 'INVALID'
                if is_valid_syntax(single_email):
                    domain = single_email.split('@')[1]
                    mx_records = get_mx_records(domain)
                    if mx_records:
                        if check_smtp(single_email, mx_records):
                            email_status = 'VALID'
                st.write(f"The email address **{single_email}** is **{email_status}**.")
            else:
                st.error("Please enter an email address.")
    elif verify_option == "CSV File":
        uploaded_file = st.file_uploader("Upload a CSV file with an 'email' column", type=["csv"])
        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)
            if 'email' in df.columns:
                df['status'] = 'Pending'
                result_placeholder = st.empty()
                result_placeholder.write(df)
                progress_bar = st.progress(0)
                total_emails = len(df)
                for index, row in df.iterrows():
                    email = row['email']
                    email_status = 'INVALID'
                    if is_valid_syntax(email):
                        domain = email.split('@')[1]
                        mx_records = get_mx_records(domain)
                        if mx_records:
                            if check_smtp(email, mx_records):
                                email_status = 'VALID'
                    df.at[index, 'status'] = email_status
                    progress = (index + 1) / total_emails
                    progress_bar.progress(progress)
                    result_placeholder.write(df)
                st.success("Email verification completed.")
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download Results as CSV",
                    data=csv,
                    file_name='email_verification_results.csv',
                    mime='text/csv',
                )
            else:
                st.error("The uploaded CSV file does not contain an 'email' column.")

# Function for AI Chat with OpenAI
def chat_with_ai():
    st.subheader("Chat with the AI Assistant")
    system_prompt = "You are a helpful assistant."
    if 'messages' not in st.session_state:
        st.session_state.messages = []

    # Display chat messages from history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Get user input
    user_input = st.chat_input("You: ")
    if user_input is not None:
        if user_input.lower() == 'exit':
            st.write("### Ending the conversation.")
            return

        # Append user input to the conversation history
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Call the OpenAI API to get the AI's response
        def get_completion(system_prompt, conversation_history):
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",  # or "gpt-4" if you have access
                messages=[{"role": "system", "content": system_prompt}] + conversation_history,
            )
            return response['choices'][0]['message']['content'].strip()

        # Get AI response and update the conversation history
        response = get_completion(system_prompt, st.session_state.messages)
        st.session_state.messages.append({"role": "assistant", "content": response})
        with st.chat_message("assistant"):
            st.markdown(response)

# Sidebar options
st.sidebar.title("Options")
option = st.sidebar.selectbox("Choose an option:", ("Verify Emails", "Chat with AI"))

# Main section that calls the respective functions
if option == "Verify Emails":
    verify_emails()
elif option == "Chat with AI":
    chat_with_ai()
