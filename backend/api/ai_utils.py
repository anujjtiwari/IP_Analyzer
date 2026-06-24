import os
import google.generativeai as genai
from concurrent.futures import ThreadPoolExecutor
import json

def load_env_file():
    current_dir = os.path.dirname(os.path.abspath(__file__)) 
    backend_dir = os.path.dirname(current_dir) 
    root_dir = os.path.dirname(backend_dir) 
    
    for path in [os.path.join(backend_dir, ".env"), os.path.join(root_dir, ".env")]:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip()
                            if val.startswith(('"', "'")) and val.endswith(('"', "'")):
                                val = val[1:-1]
                            os.environ[key] = val
            except Exception as e:
                print(f"Error loading .env file from {path}: {e}")

load_env_file()

def get_gemini_summary(category_name, data):
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return "AI Summary not configured: Set the GEMINI_API_KEY environment variable."
    
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        prompt = (
            f"You are an expert, friendly security analyst. Please write a very simple and brief summary (1-2 sentences) "
            f"explaining the results in the '{category_name}' section for a non-technical user. "
            f"Avoid technical jargon where possible, and clearly highlight if everything looks safe, or if there is something suspicious "
            f"they should be aware of (such as high abuse scores, blocklist detections, or VPN/proxy/Tor flags).\n\n"
            f"Section Data:\n{json.dumps(data, indent=2, default=str)}"
        )
        
        response = model.generate_content(prompt)
        if response and response.text:
            return response.text.strip()
        return "Unable to generate summary."
    except Exception as e:
        return f"Error generating summary: {str(e)}"

def populate_ai_summaries(results_summary):
    results_summary["ai_summary"] = {}
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        for key in results_summary:
            if key not in ["General", "ai_summary"]:
                results_summary["ai_summary"][key] = "AI Summary not configured: Set the GEMINI_API_KEY environment variable."
        return

    # Keys to summarize
    keys_to_summarize = [k for k in results_summary if k not in ["General", "ai_summary"]]
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(get_gemini_summary, key, results_summary[key]): key for key in keys_to_summarize}
        for future in futures:
            key = futures[future]
            try:
                results_summary["ai_summary"][key] = future.result()
            except Exception as e:
                results_summary["ai_summary"][key] = f"Error generating summary: {str(e)}"
