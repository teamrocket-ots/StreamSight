# Portable image for hosts that do not install apt packages for you
# (Hugging Face Spaces, Render, Railway, Fly.io, any VPS).
#
# Streamlit Community Cloud does not use this file -- it reads packages.txt
# and requirements.txt instead.

FROM python:3.12-slim

# tshark pulls in wireshark-common, whose postinst asks whether non-superusers
# may capture packets. Without a noninteractive frontend that prompt hangs the
# build. StreamSight only ever reads capture files, so the default "no" is
# correct and no capture privileges are needed.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Hugging Face Spaces expects 7860; most other hosts inject $PORT.
ENV PORT=8501
EXPOSE 8501

# Run as a non-root user. tshark refuses to run as root in some configurations,
# and there is no reason to need it for reading files.
RUN useradd --create-home --uid 1000 streamsight \
    && chown -R streamsight:streamsight /app
USER streamsight

CMD ["sh", "-c", "streamlit run app.py --server.port=${PORT:-8501} --server.address=0.0.0.0 --server.headless=true"]
