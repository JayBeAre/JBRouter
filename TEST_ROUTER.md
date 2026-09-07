# Router Test Suite (PowerShell Edition)

This file contains PowerShell-compatible `curl.exe` commands to test the `JBRouter`.

**Important:**
- Replace `https://jbrouter.alila-jj.workers.dev/v1/messages` with your local URL if running via `wrangler dev` (e.g., `http://localhost:8787/v1/messages`).
- Replace `dummy` in the authorization header if you have a different token.
- Use these **single-line commands** in your PowerShell terminal to avoid parsing issues.

---

### 1. Basic Text Completion
```powershell
curl.exe -X POST https://jbrouter.alila-jj.workers.dev/v1/messages -H "Content-Type: application/json" -H "Authorization: Bearer dummy" -d '{\"model\": \"sonnet\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello, how are you?\"}]}'
```

### 2. Tool Calling (Known Failure)
Tests the scenario that triggered the `thought_signature` error.
```powershell
curl.exe -X POST https://jbrouter.alila-jj.workers.dev/v1/messages -H "Content-Type: application/json" -H "Authorization: Bearer dummy" -d '{\"model\": \"sonnet\", \"messages\": [{\"role\": \"user\", \"content\": \"Search for news about Gemini\"}], \"tools\": [{\"name\": \"WebSearch\", \"description\": \"Search the web\", \"input_schema\": {\"type\": \"object\", \"properties\": {}}}]}'
```

### 3. Streaming Response
```powershell
curl.exe -X POST https://jbrouter.alila-jj.workers.dev/v1/messages -H "Content-Type: application/json" -H "Authorization: Bearer dummy" -d '{\"model\": \"sonnet\", \"stream\": true, \"messages\": [{\"role\": \"user\", \"content\": \"Tell me a short story.\"}]}'
```

### 4. Multi-Turn Conversation
```powershell
curl.exe -X POST https://jbrouter.alila-jj.workers.dev/v1/messages -H "Content-Type: application/json" -H "Authorization: Bearer dummy" -d '{\"model\": \"sonnet\", \"messages\": [{\"role\": \"user\", \"content\": \"My name is Gemini User.\"}, {\"role\": \"assistant\", \"content\": \"Hello Gemini User! How can I help you today?\"}, {\"role\": \"user\", \"content\": \"What is my name?\"}]}'
```

### 5. Invalid Input (Negative Test)
```powershell
curl.exe -X POST https://jbrouter.alila-jj.workers.dev/v1/messages -H "Content-Type: application/json" -H "Authorization: Bearer dummy" -d '{\"invalid\": \"json\"}'
```
