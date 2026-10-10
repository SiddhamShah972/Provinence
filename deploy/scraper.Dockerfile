FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install minimal OS dependencies for compilation, network security, and PDF export
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    pandoc \
    texlive-xetex \
    texlive-fonts-recommended \
    lmodern \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir streamlit python-dotenv langgraph

# Copy application code
COPY config/ ./config/
COPY provenance_engine/ ./provenance_engine/
COPY ui/ ./ui/

# Create non-root user and set permissions
RUN groupadd -g 10001 sandboxgroup && \
    useradd -u 10001 -g sandboxgroup -s /usr/sbin/nologin -d /app sandboxuser && \
    mkdir -p /app/output && \
    chown -R sandboxuser:sandboxgroup /app

USER sandboxuser:sandboxgroup

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "ui/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
