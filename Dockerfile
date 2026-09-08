FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --timeout 1000 --retries 10 .

COPY config ./config
COPY scripts ./scripts
COPY ui ./ui

FROM base AS streamlit

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --timeout 1000 --retries 10 ".[ui]"

FROM base AS backend

CMD ["uvicorn", "investigation_agent.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
