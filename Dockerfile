# Development/test container only. This is not an audited production image.
ARG PYTHON_VERSION=3.13
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN python -m venv "$VIRTUAL_ENV" \
    && useradd --create-home --shell /usr/sbin/nologin --uid 10001 securedoc

WORKDIR /app
COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY app.py cli_entry.py ./
COPY securedoc/ ./securedoc/
COPY scripts/ ./scripts/
COPY tests/ ./tests/

# pip runs from /opt/venv; no project package is installed in host Python.
RUN python -m pip install --no-cache-dir -r requirements.txt

USER securedoc
# No display/Tk in this test image; print headless CLI help by default.
CMD ["python", "app.py", "--help"]
