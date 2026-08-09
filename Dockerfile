# ---------- build stage ----------
# Chainguard's -dev variant has pip and a shell. It is used ONLY to resolve
# dependencies; none of it reaches the final image.
FROM cgr.dev/chainguard/python:latest-dev AS build

WORKDIR /app
COPY requirements.txt .

# Dependencies land in a venv at a fixed path so the runtime stage does not
# need to know the interpreter's minor version.
RUN python -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt


# ---------- runtime stage ----------
# NIST 800-53 CM-7 (Least Functionality) / SOC 2 CC6.1
# Distroless base: no shell, no package manager, no apt. An attacker who
# achieves execution has no tooling to pivot with, and the image cannot be
# mutated at runtime by installing anything.
FROM cgr.dev/chainguard/python:latest

WORKDIR /app

# Only the resolved venv crosses the stage boundary -- pip, build tools and
# the shell stay behind in the build stage.
COPY --from=build /app/venv /app/venv

# Application code and the control specification it implements.
COPY evidence_collector.py control-spec.md ./

ENV PATH="/app/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# NIST 800-53 AC-6 (Least Privilege)
# Chainguard images default to nonroot; declared explicitly so the control is
# visible to a reviewer rather than inherited silently from the base image.
USER nonroot

# NIST 800-53 IA-5 (Authenticator Management)
# No credentials are baked into the image. AWS identity is supplied at runtime
# by mounting the profile read-only, or by a task/execution role in a real
# deployment. See README for the bootstrap exception on the current IAM user.
ENTRYPOINT ["python", "evidence_collector.py"]
