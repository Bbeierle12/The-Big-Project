# ===========================================================================
# Stage 1: Rust builder
# Compiles all pure-Rust workspace crates (excludes PyO3/FFI crates that
# require Python headers or special linker setup).
# ===========================================================================
FROM rust:1.75-slim AS rust-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for better layer caching -- dependencies are resolved
# and downloaded before the actual source code is copied.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

RUN cargo build --release --workspace \
    --exclude netsec-python \
    --exclude netsec-ffi

# ===========================================================================
# Stage 2: Python wheel builder
# Uses maturin to compile the netsec-python (PyO3) crate into a Python wheel
# that can be pip-installed in the final runtime image.
# ===========================================================================
FROM rust:1.75-slim AS wheel-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3.12-dev \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --break-system-packages maturin>=1.7

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

RUN maturin build --release \
    -m crates/netsec-python/Cargo.toml \
    --out /wheels

# ===========================================================================
# Stage 3: Runtime
# Minimal Python image with only the runtime dependencies needed to operate
# the netsec platform (nmap, tshark, clamav, fail2ban).
# ===========================================================================
FROM python:3.12-slim AS runtime

# Install runtime system dependencies required by security tool adapters.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    tshark \
    clamav \
    fail2ban \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Rust binaries (if any standalone binaries were produced) --------------
COPY --from=rust-builder /app/target/release/netsec* /usr/local/bin/

# --- Native Python extension (.whl) ----------------------------------------
COPY --from=wheel-builder /wheels/*.whl /tmp/wheels/
RUN pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

# --- Python package dependencies -------------------------------------------
# Copy pyproject.toml first so pip install only re-runs when deps change.
COPY pyproject.toml ./
RUN pip install --no-cache-dir . \
    && rm -rf /root/.cache/pip

# --- Application source & config -------------------------------------------
COPY config/ ./config/
COPY python/ ./python/
COPY migrations/ ./migrations/
COPY alembic.ini ./

# --- Non-root user ----------------------------------------------------------
RUN useradd --create-home --shell /bin/bash netsec \
    && chown -R netsec:netsec /app
USER netsec

EXPOSE 8420

CMD ["python", "-m", "netsec"]
