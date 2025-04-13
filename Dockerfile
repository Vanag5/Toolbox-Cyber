FROM python:3.10-slim
WORKDIR /src/toolbox
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ .
ENTRYPOINT ["python", "-m", "toolbox"]

# Create necessary directories
RUN mkdir -p toolbox/static

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000
ENV FLASK_DEBUG=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/src/toolbox

EXPOSE 5000

CMD ["flask", "run"]
