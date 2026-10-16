# Sahajta Odoo MCP server: company-wide Claude connector.
FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    MCP_HOST=0.0.0.0 MCP_PORT=8000 MCP_DATA_DIR=/data
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin mcp \
 && mkdir -p /data && chown mcp /data && chmod 700 /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels
USER mcp
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"
CMD ["sahajta-odoo-mcp", "http"]
