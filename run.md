# Run HoneyPrompt locally

Open two PowerShell terminals from the project root.

## Backend

In the first terminal:

```powershell
cd backend
py -m pip install -r requirements.txt
py -m uvicorn main:app --reload --port 8000
```

The API runs at `http://127.0.0.1:8000`. Check `http://127.0.0.1:8000/status` for its health status.

Chat requests require a valid Groq API key in `backend/.env`:

```text
GROQ_API_KEY=your_groq_api_key
```

Restart the backend after changing the key.

## Frontend

In the second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open the Vite URL printed in the terminal, normally `http://localhost:5173`.