import json
import requests
from core.database import get_setting

def check_ollama_status():
    """
    Checks if local Ollama server is running and returns available models.
    """
    try:
        r = requests.get("http://127.0.0.1:11434/api/tags", timeout=2)
        if r.ok:
            data = r.json()
            models = [m.get("name") for m in data.get("models", [])]
            return {"active": True, "models": models}
    except Exception:
        pass
    return {"active": False, "models": []}

def stream_ai_response(provider, model, messages, api_key=None):
    """
    Generator yielding Server-Sent Events (SSE) data chunks directly to the UI.
    """
    if not api_key:
        api_key = get_setting(f"api_key_{provider}", "")

    # 1. OLLAMA (100% Offline / Local)
    if provider == "ollama":
        url = "http://127.0.0.1:11434/api/chat"
        payload = {
            "model": model or "llama3.2",
            "messages": messages,
            "stream": True
        }
        try:
            r = requests.post(url, json=payload, stream=True, timeout=60)
            if not r.ok:
                yield f"data: {json.dumps({'error': f'Ollama error: {r.status_code} - {r.text}'})}\n\n"
                return

            for line in r.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line.decode("utf-8"))
                        text = chunk.get("message", {}).get("content", "")
                        if text:
                            yield f"data: {json.dumps({'chunk': text})}\n\n"
                    except Exception:
                        pass
            yield f"data: {json.dumps({'done': True})}\n\n"
            return
        except Exception as e:
            yield f"data: {json.dumps({'error': f'Cannot connect to Ollama at http://127.0.0.1:11434. Make sure Ollama is installed and running.'})}\n\n"
            return

    # If cloud provider and no key
    if not api_key or api_key.strip() == "":
        yield f"data: {json.dumps({'error': f'API Key is required for provider {provider}. Please configure your key in Settings.'})}\n\n"
        return

    # 2. ANTHROPIC CLAUDE
    if provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        }
        
        # Format messages for Anthropic
        system_msg = "You are Suresh Pro Studio 2.0 AI Assistant. Provide concise, expert engineering and cybersecurity solutions."
        user_messages = []
        for m in messages:
            if m.get("role") == "system":
                system_msg = m.get("content", "")
            else:
                user_messages.append({"role": m.get("role"), "content": m.get("content")})

        payload = {
            "model": model or "claude-3-5-sonnet-20241022",
            "system": system_msg,
            "messages": user_messages,
            "max_tokens": 4096,
            "stream": True
        }

        try:
            r = requests.post(url, headers=headers, json=payload, stream=True, timeout=60)
            if not r.ok:
                yield f"data: {json.dumps({'error': f'Anthropic API error: {r.status_code} - {r.text}'})}\n\n"
                return

            for line in r.iter_lines():
                if line:
                    line_str = line.decode("utf-8")
                    if line_str.startswith("data: "):
                        data_part = line_str[6:]
                        if data_part.strip() == "[DONE]":
                            break
                        try:
                            event = json.loads(data_part)
                            if event.get("type") == "content_block_delta":
                                chunk = event.get("delta", {}).get("text", "")
                                if chunk:
                                    yield f"data: {json.dumps({'chunk': chunk})}\n\n"
                        except Exception:
                            pass
            yield f"data: {json.dumps({'done': True})}\n\n"
            return
        except Exception as e:
            yield f"data: {json.dumps({'error': f'Network error communicating with Anthropic: {str(e)}'})}\n\n"
            return

    # 3. GOOGLE GEMINI
    elif provider == "gemini":
        gemini_model = model or "gemini-2.0-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{gemini_model}:streamGenerateContent?key={api_key}&alt=sse"
        
        # Convert messages to Gemini contents
        contents = []
        for m in messages:
            role = "user" if m.get("role") == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m.get("content", "")}]})

        payload = {"contents": contents}

        try:
            r = requests.post(url, json=payload, stream=True, timeout=60)
            if not r.ok:
                yield f"data: {json.dumps({'error': f'Gemini API error: {r.status_code} - {r.text}'})}\n\n"
                return

            for line in r.iter_lines():
                if line:
                    line_str = line.decode("utf-8")
                    if line_str.startswith("data: "):
                        data_part = line_str[6:]
                        try:
                            event = json.loads(data_part)
                            candidates = event.get("candidates", [])
                            if candidates:
                                parts = candidates[0].get("content", {}).get("parts", [])
                                for p in parts:
                                    text = p.get("text", "")
                                    if text:
                                        yield f"data: {json.dumps({'chunk': text})}\n\n"
                        except Exception:
                            pass
            yield f"data: {json.dumps({'done': True})}\n\n"
            return
        except Exception as e:
            yield f"data: {json.dumps({'error': f'Network error communicating with Gemini: {str(e)}'})}\n\n"
            return

    # 4. OPENAI / DEEPSEEK / OPENROUTER / GROQ (OpenAI Compatible)
    else:
        endpoint_map = {
            "openai": ("https://api.openai.com/v1/chat/completions", model or "gpt-4o"),
            "deepseek": ("https://api.deepseek.com/chat/completions", model or "deepseek-chat"),
            "openrouter": ("https://openrouter.ai/api/v1/chat/completions", model or "anthropic/claude-3.5-sonnet"),
            "groq": ("https://api.groq.com/openai/v1/chat/completions", model or "llama-3.3-70b-versatile")
        }

        url, default_model = endpoint_map.get(provider, ("https://api.openai.com/v1/chat/completions", "gpt-4o"))
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        if provider == "openrouter":
            headers["HTTP-Referer"] = "http://localhost"
            headers["X-Title"] = "Suresh Pro Studio"

        payload = {
            "model": model or default_model,
            "messages": messages,
            "stream": True,
            "temperature": 0.5
        }

        try:
            r = requests.post(url, headers=headers, json=payload, stream=True, timeout=60)
            if not r.ok:
                yield f"data: {json.dumps({'error': f'{provider.title()} API error: {r.status_code} - {r.text}'})}\n\n"
                return

            for line in r.iter_lines():
                if line:
                    line_str = line.decode("utf-8")
                    if line_str.startswith("data: "):
                        data_part = line_str[6:]
                        if data_part.strip() == "[DONE]":
                            break
                        try:
                            event = json.loads(data_part)
                            delta = event.get("choices", [{}])[0].get("delta", {})
                            chunk = delta.get("content", "")
                            if chunk:
                                yield f"data: {json.dumps({'chunk': chunk})}\n\n"
                        except Exception:
                            pass
            yield f"data: {json.dumps({'done': True})}\n\n"
            return
        except Exception as e:
            yield f"data: {json.dumps({'error': f'Network error communicating with {provider}: {str(e)}'})}\n\n"
            return
