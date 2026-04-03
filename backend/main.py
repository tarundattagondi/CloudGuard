from fastapi import FastAPI

app = FastAPI(title="CloudGuard", description="AWS Security Misconfiguration Scanner & Risk Dashboard")


@app.get("/health")
def health_check():
    return {"status": "healthy"}
