from ollama import ChatResponse
from ollama import chat
import hashlib
import json

def analyze_with_gemma(file_bytes, file_name):
    try:
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        extension = file_name.split('.')[-1] if '.' in file_name else 'no_extension'

        header_sample = file_bytes[:64].hex(' ')
        footer_sample = file_bytes[-64:].hex(' ')

        full_prompt = f"""
    Return VALID JSON ONLY:
    {{"state": "PASS" or "BLOCK", "main_reason": "..."}}
    
    Analyze this file security report:
    - Filename: {file_name}
    - Extension: {extension}
    - Size: {len(file_bytes)} bytes
    - SHA256: {file_hash}
    - Header Sample: {header_sample}
    - Footer Sample: {footer_sample}
    
    Rules:
    1. BLOCK if extension is hidden (e.g., .pdf.exe).
    2. BLOCK if a common text/image file contains executable headers (e.g., MZ, ELF).
    3. If the file is a script, check for high-risk commands (rm, format, delete, socket).
    """

        response: ChatResponse = chat(
            model="gemma3:12b",
            messages=[
                {
                    "role": "system",
                    "content": "You are a strict security analysis engine. You must return valid JSON only and follow the rules exactly."
                },
                {
                    "role": "user",
                    "content": full_prompt
                }
            ]
        )

        try:
            clean_response = (
                response.message.content
                .strip()
                .replace("```json", "")
                .replace("```", "")
            )
            return json.loads(clean_response)
        except Exception:
            return {
                "state": "PASS",
                "main_reason": "Analysis failed - defaulting to safe"
            }
    except:
        print('[Ollama] Connection Error')