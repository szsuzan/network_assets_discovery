FROM python:3.11-slim

WORKDIR /app

# Install system scanning tools.
RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    curl \
    ca-certificates \
    libpcap-dev \
    snmp \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libharfbuzz0b \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    gcc \
    fonts-dejavu \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
