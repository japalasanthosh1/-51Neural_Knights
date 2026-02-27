# -51Neural_Knights

FastAPI-based PII leakage scanner with a custom static frontend and an additional `clerk-javascript` project folder.

## Project Structure

```text
66hack/
|-- main.py
|-- pii_engine.py
|-- web_scanner.py
|-- social_api_scanner.py
|-- email_discovery_scanner.py
|-- requirements.txt
|-- README.md
|-- static/
|   |-- index.html
|   |-- style.css
|   `-- app.js
|-- clerk-javascript/
|   |-- .env
|   |-- .gitignore
|   |-- index.html
|   |-- package.json
|   |-- package-lock.json
|   |-- tsconfig.json
|   |-- src/
|   |   |-- main.js
|   |   `-- style.css
|   |-- public/
|   |   `-- vite.svg
|   |-- dist/
|   |   |-- index.html
|   |   |-- vite.svg
|   |   `-- assets/
|   |       |-- index-Cq48blt_.css
|   |       `-- index-CW9MT27T.js
|   `-- node_modules/            (installed JS dependencies)
|-- .venv/                       (Python virtual environment)
`-- __pycache__/                 (Python bytecode cache)
```

## Main Components

- `main.py`: FastAPI app and API routes for scanning, monitoring, stats, and streaming.
- `pii_engine.py`: Core PII detection engine and model/rule orchestration.
- `web_scanner.py`: Web search and URL content scanning pipeline.
- `social_api_scanner.py`: Social profile scanning integrations.
- `email_discovery_scanner.py`: Email-based footprint and leakage discovery.
- `static/*`: Frontend UI (HTML, CSS, JavaScript) used by the FastAPI app.
- `clerk-javascript/*`: Separate JavaScript project (build + source artifacts).

## Run (Python app)

```bash
pip install -r requirements.txt
python main.py
```

App serves at `http://localhost:8001`.
