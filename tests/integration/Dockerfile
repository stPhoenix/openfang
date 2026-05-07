# Tiny image for the live-integration pytest runner.
# Used by docker-compose.tests.yml as the `openfang-tests` service.
FROM python:3.13-slim

WORKDIR /tests
RUN pip install --no-cache-dir --root-user-action=ignore \
        pytest==8.3.4 \
        httpx==0.28.1

COPY conftest.py test_live.py ./
ENV PYTHONUNBUFFERED=1
CMD ["pytest", "-v", "--tb=short", "--color=yes"]
