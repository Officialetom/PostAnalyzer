# --- Streamlit Version of Mental Health Post Analyzer ---
import streamlit as st
import sqlite3
import pandas as pd
from textblob import TextBlob
from collections import Counter
import matplotlib.pyplot as plt
from datetime import datetime
from dateutil import parser
import nltk
nltk.download('punkt')

# --- Database Setup ---
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
)''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS logs (
    username TEXT,
    date TEXT,
    sentiment REAL,
    keywords TEXT,
    flagged INTEGER,
    recommendation TEXT
)''')
conn.commit()

# --- Analyzer Functions ---
def analyze_posts(posts):
    all_text = " ".join(posts)
    keywords = Counter(all_text.split()).most_common(5)
    sentiments = [TextBlob(post).sentiment.polarity for post in posts]
    average_sentiment = sum(sentiments) / len(sentiments)
    flagged = average_sentiment < -0.2
    recommendation = "Consider reaching out for support." if flagged else "Keep monitoring your mood."
    return average_sentiment, keywords, flagged, recommendation, sentiments

# --- Chart Function ---
def show_sentiment_chart(timestamps, sentiments):
    try:
        dates = [parser.parse(t) for t in timestamps]  # Auto-parses various date formats
        fig, ax = plt.subplots()
        ax.plot(dates, sentiments, marker='o', linestyle='-')
        ax.set_title('Sentiment Trend Over Time')
        ax.set_xlabel('Date')
        ax.set_ylabel('Sentiment Polarity')
        ax.grid(True)
        st.pyplot(fig)
    except Exception as e:
        st.error(f"Error plotting sentiment chart: {e}")

# --- Save to Logs ---
def log_analysis(username, sentiment, keywords, flagged, recommendation):
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    keyword_str = ", ".join([kw[0] for kw in keywords])
    cursor.execute('''INSERT INTO logs (username, date, sentiment, keywords, flagged, recommendation)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                   (username, date, sentiment, keyword_str, int(flagged), recommendation))
    conn.commit()

# --- User Authentication ---
def register_user(username, password):
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def authenticate_user(username, password):
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    return cursor.fetchone() is not None

# --- Streamlit App ---
st.set_page_config(page_title="Mental Health Post Analyzer", layout="centered")
st.title("🧠 Mental Health Post Analyzer")

menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Menu", menu)

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.analysis_done = False
    st.session_state.analysis_data = {}

if choice == "Register":
    st.subheader("Create New Account")
    new_user = st.text_input("Username")
    new_password = st.text_input("Password", type='password')
    if st.button("Register"):
        if register_user(new_user, new_password):
            st.success("Account created successfully! Go to Login.")
        else:
            st.error("Username already exists.")

elif choice == "Login":
    st.subheader("Login to your account")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    if st.button("Login"):
        if authenticate_user(username, password):
            st.success(f"Welcome {username}!")
            st.session_state.logged_in = True
            st.session_state.username = username
        else:
            st.error("Invalid username or password")

# --- Main Analyzer Page ---
if st.session_state.logged_in:
    st.subheader("📊 Analyze Mental Health Posts")

    uploaded_file = st.file_uploader("Upload a CSV file (must contain 'post_text' and 'timestamp' columns)", type=["csv"])

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)

            if 'post_text' not in df.columns or 'timestamp' not in df.columns:
                st.error("CSV must include 'post_text' and 'timestamp' columns.")
            else:
                user_posts = df['post_text'].dropna().tolist()
                timestamps = df['timestamp'].tolist()

                if st.button("Run Analysis"):
                    if not user_posts:
                        st.warning("No posts found in the file.")
                    else:
                        sentiment, keywords, flagged, recommendation, sentiments = analyze_posts(user_posts)

                        st.markdown(f"**Sentiment Score:** `{sentiment:.2f}`")
                        st.markdown(f"**Top Keywords:** {', '.join([kw[0] for kw in keywords])}")
                        st.markdown(f"**Flagged:** {'🔴 Yes' if flagged else '🟢 No'}")
                        st.markdown(f"**Recommendation:** _{recommendation}_")

                        show_sentiment_chart(timestamps, sentiments)
                        log_analysis(st.session_state.username, sentiment, keywords, flagged, recommendation)

                        # Save analysis state for export
                        st.session_state.analysis_done = True
                        st.session_state.analysis_data = {
                            "sentiment": sentiment,
                            "keywords": keywords,
                            "flagged": flagged,
                            "recommendation": recommendation
                        }

        except Exception as e:
            st.error(f"Failed to process file: {e}")
    else:
        st.info("Please upload a CSV file to begin analysis.")

    # --- Export Button (Always visible after analysis) ---
    if st.session_state.analysis_done:
        if st.button("Export Result"):
            result = st.session_state.analysis_data
            with open("analysis_result.txt", "w") as file:
                file.write(f"User: {st.session_state.username}\n")
                file.write(f"Sentiment Score: {result['sentiment']:.2f}\n")
                file.write(f"Top Keywords: {', '.join([kw[0] for kw in result['keywords']])}\n")
                file.write(f"Flagged: {'Yes' if result['flagged'] else 'No'}\n")
                file.write(f"Recommendation: {result['recommendation']}\n")
            st.success("✅ Result exported to `analysis_result.txt`")
