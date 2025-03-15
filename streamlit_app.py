import streamlit as st
import google.generativeai as genai
import random  # Import the random module

# Configure the API key securely from Streamlit's secrets
genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])

# Streamlit App UI
st.title("AI-Powered Code Converter")
st.write("Convert code between different programming languages using AI. Select the languages and input your code.")

# Dropdown for selecting the source and target programming languages
source_language = st.selectbox("Select Source Language", ["Python", "JavaScript", "Java", "C++", "Ruby"])
target_language = st.selectbox("Select Target Language", ["Python", "JavaScript", "Java", "C++", "Ruby"])

# Code input field
source_code = st.text_area("Enter your source code here:", height=300)

# Button to generate converted code
if st.button("Convert Code"):
    if not source_code:
        st.error("Please provide the source code.")
    else:
        try:
            # Load and configure the model
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            # Prepare the prompt for the model to convert the code
            prompt = f"Convert the following {source_language} code to {target_language}:\n\n{source_code}"

            # Generate response from the model
            response = model.generate_content(prompt)
            
            # Display converted code
            st.subheader(f"Converted {source_language} to {target_language} Code:")
            st.code(response.text, language=target_language.lower())

            # Provide an explanation of the converted code
            explanation_prompt = f"Explain the following {target_language} code:\n\n{response.text}"
            explanation = model.generate_content(explanation_prompt)

            # Display explanation of the converted code
            st.subheader(f"Explanation of {target_language} Code:")
            st.write(explanation.text)
        except Exception as e:
            st.error(f"Error: {e}")

# Add a fun feature: Show random programming jokes or tips to users
st.sidebar.header("Fun Extras")
# Set the checkbox to be checked by default
show_joke = st.sidebar.checkbox("Show Programming Joke", value=True)  # Set default to True
if show_joke:
    jokes = [
        "Why do programmers prefer dark mode? Because the light attracts bugs!",
        "Why do Java developers wear glasses? Because they can't C#.",
        "A programmer's wife tells him, 'While you’re at it, clean the kitchen.' The programmer replies, 'I’ll clean the kitchen once the kitchen-cleaning algorithm is complete and tested.'",
        "Why don’t programmers like nature? It has too many bugs."
    ]
    st.sidebar.write(f"**Joke:** {random.choice(jokes)}")  # Use random.choice() from the random module

# Provide an option for users to download their converted code
st.sidebar.header("Download Converted Code")
download_code = st.sidebar.button("Download Converted Code")
if download_code:
    try:
        # Saving the converted code as a .txt file for download
        with open("converted_code.txt", "w") as f:
            f.write(response.text)
        st.sidebar.success("The converted code has been saved as 'converted_code.txt'. You can download it now.")
    except Exception as e:
        st.sidebar.error(f"Error while saving the file: {e}")
