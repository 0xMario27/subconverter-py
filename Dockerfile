FROM python:3.11-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml .
COPY src/ src/
COPY base/ base/

# Install runtime deps directly, skip building the package
RUN uv pip install --system flask waitress requests pyyaml jinja2 toml

ENV TZ=Asia/Shanghai
ENV PYTHONPATH=/app/src
EXPOSE 25500/tcp
VOLUME ["/app/base/cache"]
WORKDIR /app/base
CMD ["python", "-m", "subconverter.main"]
