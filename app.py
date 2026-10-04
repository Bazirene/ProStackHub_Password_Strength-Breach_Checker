import streamlit as st
import pandas as pd
import sqlite3
from checker import check_pwned_password, evaluate_strength, generate_password, check_email_exposure
from database import init_db, log_audit

init_db()

st.set_page_config(page_title="Password & Breach Auditor", page_icon="🔐", layout="wide")
st.title("🔐 Password Strength & Breach Checker")

tabs = st.tabs(["Auditor (Password & Email)", "Password Generator", "SQLite Audit History"])

# Tab 1: Audit
with tabs[0]:
    st.subheader("Credential Security Audit")
    
    col1, col2 = st.columns(2)
    with col1:
        pwd_input = st.text_input("Enter password to test:", type="password")
        if st.button("Analyze Password"):
            if pwd_input:
                score, feedback, crack_time = evaluate_strength(pwd_input)
                breach_count = check_pwned_password(pwd_input)
                
                severity = "Critical" if breach_count > 0 else ("High" if score <= 1 else ("Medium" if score < 4 else "Low"))
                masked = pwd_input[:2] + "****" if len(pwd_input) > 2 else "****"
                log_audit("Web_Interface", masked, score, breach_count, severity)
                
                score_labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
                st.progress((score + 1) / 5)
                st.write(f"**Score:** {score_labels[score]} ({score}/4)")
                st.write(f"**Estimated Crack Time:** {crack_time}")
                
                if breach_count > 0:
                    st.error(f"⚠️ Compromised! Found in **{breach_count:,}** data breaches (via HIBP k-Anonymity).")
                else:
                    st.success("✅ Clean! No records found in known public breaches.")
                    
                if feedback:
                    st.info("Suggestions:\n- " + "\n- ".join(feedback))

    with col2:
        email_input = st.text_input("Enter email address to test:")
        if st.button("Check Email"):
            if email_input and "@" in email_input:
                exposed = check_email_exposure(email_input)
                severity = "High" if exposed else "Low"
                log_audit("Email_Check", email_input, 0, 1 if exposed else 0, severity)
                
                if exposed:
                    st.error(f"⚠️ Email domain associated with recorded breaches.")
                else:
                    st.success("✅ No direct leak alerts found for this address.")
            else:
                st.warning("Please enter a valid email address.")

# Tab 2: Generator
with tabs[1]:
    st.subheader("Secure Password & Passphrase Generator")
    mode = st.radio("Style", ["Random Characters", "Memorable Passphrase"])
    
    if mode == "Random Characters":
        length = st.slider("Length", 8, 32, 16)
        syms = st.checkbox("Include Symbols", value=True)
        if st.button("Generate Password"):
            st.code(generate_password(length=length, use_symbols=syms, memorable=False))
    else:
        if st.button("Generate Passphrase"):
            st.code(generate_password(memorable=True))

# Tab 3: SQLite History
with tabs[2]:
    st.subheader("SQLite Flagged Events & Audit Trail")
    conn = sqlite3.connect("breach_history.db")
    df = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 25", conn)
    conn.close()
    st.dataframe(df, use_container_width=True)
