# AI-powered log analyser
# Takes your existing log-parser output
# Sends it to an LLM via OpenRouter
# Returns structured threat analysis in JSON

import os, json, time
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.environ.get("OPENROUTER_API_KEY")

if not api_key:
    raise RuntimeError(
        "OPENROUTER_API_KEY not found. Check that a .env file exists in the "
        "project root and contains OPENROUTER_API_KEY=your_key_here"
    )

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=api_key,
)

import time

def analyse_threat(log_summary: str, max_retries: int = 3) -> dict:
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="google/gemma-4-26b-a4b-it:free",
                max_tokens=1024,
                messages=[{
                    "role": "user",
                    "content": f"""Analyse this security log summary and return JSON with:
                    - threat_level (LOW/MEDIUM/HIGH/CRITICAL)
                    - attack_type
                    - recommended_action
                    - mitre_technique

                    Log summary: {log_summary}

                    Return only valid JSON, no markdown fences, no explanation."""
                }]
            )
            break
        except Exception as e:
            if "429" in str(e) and attempt < max_retries - 1:
                wait = 2 ** attempt  # 1s, 2s, 4s
                print(f"[!] Rate limited, retrying in {wait}s...")
                time.sleep(wait)
                continue
            return {"error": f"API call failed: {e}"}

    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.strip("`").removeprefix("json").strip()
    print("=== RAW MODEL OUTPUT ===")
    print(raw)
    print("========================")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "Model did not return valid JSON", "raw_response": raw}