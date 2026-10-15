FROM docker.io/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
WORKDIR /app
COPY --chmod=0755 response /app/response
USER 1000:1000
CMD ["python", "-m", "response.v1.server"]
