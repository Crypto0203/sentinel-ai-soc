// ═══════════════════════════════════════════════════════════════════
//   CRYSTAL AI BRAIN CONTROLLER
// ═══════════════════════════════════════════════════════════════════

const PERSONAS = {
  architect: "You are Suresh Pro Studio 2.0 Senior Software Architect. Provide robust, high-performance architectures, clean patterns, and complete code.",
  cyber: "You are Suresh Pro Studio 2.0 Lead Cybersecurity Forensics Specialist. Specialize in email header spoofing, phishing analysis, and incident mitigation.",
  automation: "You are Suresh Pro Studio 2.0 Python Automation Specialist. Build clean, resilient background scripts and data pipelines.",
  copywriter: "You are Suresh Pro Studio 2.0 Executive Tech Copywriter. Write concise, compelling technical summaries and reports."
};

let chatMessages = [];
let isAiGenerating = false;

function onAiProviderChange() {
  const provider = document.getElementById('ai-provider-select').value;
  const modelInput = document.getElementById('ai-model-input');
  const defaults = {
    ollama: "llama3.2",
    anthropic: "claude-3-5-sonnet-20241022",
    gemini: "gemini-2.0-flash",
    deepseek: "deepseek-chat",
    openai: "gpt-4o"
  };
  modelInput.value = defaults[provider] || "llama3.2";
}

function clearAiChat() {
  chatMessages = [];
  const history = document.getElementById('chat-history');
  history.innerHTML = `
    <div class="chat-bubble ai">
      <strong>💎 Suresh Crystal AI Studio 2.0</strong><br>
      Conversation reset. What would you like to build or analyze today?
    </div>
  `;
  showToast("Chat reset");
}

async function sendAiMessage() {
  if (isAiGenerating) return;

  const inputEl = document.getElementById('ai-user-input');
  const userText = inputEl.value.trim();
  if (!userText) return;

  inputEl.value = "";
  const provider = document.getElementById('ai-provider-select').value;
  const model = document.getElementById('ai-model-input').value.trim();
  const personaKey = document.getElementById('ai-persona-select').value;

  // Add User Message
  appendChatBubble('user', userText);

  // Initialize System prompt if empty
  if (chatMessages.length === 0) {
    chatMessages.push({ role: "system", content: PERSONAS[personaKey] || PERSONAS.architect });
  }
  chatMessages.push({ role: "user", content: userText });

  // Create AI Streaming Bubble
  const aiBubble = appendChatBubble('ai', 'Thinking...');
  isAiGenerating = true;
  document.getElementById('ai-send-btn').disabled = true;

  try {
    const response = await fetch(`${API_BASE}/api/ai/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider,
        model,
        messages: chatMessages
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      aiBubble.innerHTML = `<span style="color:var(--red);">⚠️ Error: ${err.error || 'Connection to backend AI gateway failed.'}</span>`;
      isAiGenerating = false;
      document.getElementById('ai-send-btn').disabled = false;
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let accumulatedText = "";
    aiBubble.innerHTML = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value, { stream: true });
      const lines = chunk.split("\n");

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.error) {
              accumulatedText += `\n\n**Error:** ${data.error}`;
            } else if (data.chunk) {
              accumulatedText += data.chunk;
            }
            aiBubble.innerHTML = marked.parse(accumulatedText);
            document.querySelectorAll('pre code').forEach((el) => {
              hljs.highlightElement(el);
            });
            const history = document.getElementById('chat-history');
            history.scrollTop = history.scrollHeight;
          } catch (e) {}
        }
      }
    }

    chatMessages.push({ role: "assistant", content: accumulatedText });

  } catch (e) {
    aiBubble.innerHTML = `<span style="color:var(--red);">⚠️ Network error: ${e.message}</span>`;
  } finally {
    isAiGenerating = false;
    document.getElementById('ai-send-btn').disabled = false;
  }
}

function appendChatBubble(role, initialContent) {
  const history = document.getElementById('chat-history');
  const bubble = document.createElement('div');
  bubble.className = `chat-bubble ${role}`;
  bubble.innerHTML = role === 'user' ? escapeHtml(initialContent).replace(/\n/g, '<br>') : initialContent;
  history.appendChild(bubble);
  history.scrollTop = history.scrollHeight;
  return bubble;
}

function escapeHtml(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}

// Enter Key to Send
window.addEventListener('DOMContentLoaded', () => {
  const inputEl = document.getElementById('ai-user-input');
  if (inputEl) {
    inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendAiMessage();
      }
    });
  }
});
