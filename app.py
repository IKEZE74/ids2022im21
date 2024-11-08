import streamlit as st
import pandas as pd
import dns.resolver
import smtplib
from email_validator import validate_email, EmailNotValidError
from groq import Groq
import os

# Set your Groq API Key
os.environ["GROQ_API_KEY"] = st.secrets["GROQ_API_KEY"]
client = Groq()

# Function to get completion from Groq
def get_completion(system_prompt, conversation_history):
    response = client.chat.completions.create(
        model="llama-3.1-70b-versatile",
        messages=[{"role": "system", "content": system_prompt}] + conversation_history,
    )
    return response.choices[0].message.content.strip()

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

def main():
    # Set page title
    st.title("Email Verification App with Chat")

    # Sidebar options
    st.sidebar.title("Options")
    option = st.sidebar.selectbox(
        "Choose an option:",
        ("Verify Single Email", "Verify Emails from CSV", "Chat with AI Bot")
    )

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

    # Chat with AI Bot
    elif option == "Chat with AI Bot":
        st.subheader("Conversational AI Bot")
        st.write("Chat with the AI assistant below.")

        system_prompt = "You are a helpful assistant."

        if 'messages' not in st.session_state:
            st.session_state.messages = []

        # Display chat messages from history on app rerun
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        # Accept user input
        user_input = st.chat_input("You: ")

        if user_input is not None:
            if user_input.lower() == 'exit':
                st.write("### Ending the conversation.")
                return

            # Add user message to conversation history
            st.session_state.messages.append({"role": "user", "content": user_input})
            with st.chat_message("user"):
                st.markdown(user_input)

            # Get the LLM's response
            response = get_completion(system_prompt, st.session_state.messages)

            # Add assistant's response to conversation history
            st.session_state.messages.append({"role": "assistant", "content": response})

            with st.chat_message("assistant"):
                st.markdown(response)

if __name__ == "__main__":
    main()
