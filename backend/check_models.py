import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables to get the API Key
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("ERROR: GEMINI_API_KEY not found in .env file.")
else:
    print(f"Authentication successful. Key found: {api_key[:5]}...*****")
    
    try:
        genai.configure(api_key=api_key)
        
        print("\n--- Available Models for your API Key ---")
        available_models = []
        
        # List all models available to your account
        for m in genai.list_models():
            # We only care about models that can generate text (generateContent)
            if 'generateContent' in m.supported_generation_methods:
                print(f"- {m.name}")
                available_models.append(m.name)
        
        if not available_models:
            print("\n[WARNING] No text generation models found. Check your Google Cloud/AI Studio permissions.")
        else:
            print("\n-----------------------------------------")
            print(f"Please copy one of the names above (e.g., 'models/gemini-pro') to use in main.py")

    except Exception as e:
        print(f"\n[FATAL ERROR] Could not connect to Google API: {e}")