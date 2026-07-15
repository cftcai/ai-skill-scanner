# Dockerfile for ai-skill-scanner
# Provides isolated, minimal execution environment for scanning untrusted public skills.
# Run with: docker build -t ai-skill-scanner .
# docker run --rm -v $(pwd)/skills:/scan:ro ai-skill-scanner --path /scan
# For GitHub scans the container requires outbound network for git clone.

FROM python:3.11-slim

# Install only git (required for --github-url). No other packages.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash scanner

WORKDIR /app

# Copy scanner
COPY scanner.py /app/scanner.py
RUN chmod +x /app/scanner.py

# Switch to non-root
USER scanner

# Default to CLI help if no args
ENTRYPOINT ["python", "/app/scanner.py"]
CMD ["--help"]