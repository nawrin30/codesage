# CodeSage AI

A full-stack Python code review starter with a React + TypeScript + Vite frontend and FastAPI backend. Static analysis works without an AI key. This archive focuses on a runnable core: real AST checks, optional Ruff/Bandit integrations, SQLite development storage, user registration/login, review history, exports, Docker setup, and tests. GitHub OAuth and production-grade deployment hardening are documented as extension points rather than falsely claimed as implemented.

## Requirements
- Python 3.11+
- Node.js 20+
- npm

## Run locally

### Backend
```bash
cd backend
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env  # Windows; macOS/Linux: cp .env.example .env
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

### Frontend
In a second terminal:
```bash
cd frontend
npm install
npm run dev
```
Open the URL Vite prints (normally http://localhost:5173).

Default development database is SQLite (`sqlite:///./codesage.db`). For PostgreSQL, set `DATABASE_URL` in `backend/.env`, for example `postgresql+psycopg://codesage:password@localhost:5432/codesage`.

## Configuration
See `backend/.env.example`. Set a long random `JWT_SECRET` before use beyond local development. `OPENAI_API_KEY` is optional; the core static analyzer continues to work without it. Do not commit `.env`.

## Tests
```bash
cd backend
pytest
```
Frontend production build:
```bash
cd frontend
npm run build
```

## Included functionality
- Register/login using bcrypt password hashing and signed JWT bearer tokens.
- Protected review API and per-user review history.
- Python syntax checks and AST checks for broad exceptions, `eval`/`exec`, `subprocess` shell usage, and bare `except`.
- Optional Ruff and Bandit findings when installed.
- Severity filters, search, finding details, suggested fixes, copy/apply suggestion, JSON/Markdown export.
- Dark/light theme toggle and responsive layout.
- Sample code, file upload, clear action, history search/open/delete.

## Security and scope notes
- Submitted code is parsed/analyzed but never executed.
- AST rules are heuristics and cannot find every bug or vulnerability.
- AI explanation is not wired to an external provider in this core archive; the analyzer remains deterministic when no provider is configured. Add an LLM adapter server-side before enabling AI features.
- GitHub OAuth/repository browsing is not implemented in this starter. The UI does not pretend it is connected.
- SQLite is intended for local development. Review source is stored in the database; delete a review to remove its saved code. Do not submit secrets or sensitive code.
- For production, add HTTPS, CSRF/origin protections appropriate to deployment, account verification, password reset, robust rate limiting, key rotation, migrations, monitoring, and a security review.
