from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Mock backend is running"}

@app.get("/customers")
def get_customers():
    return {"customers": ["Ali", "Sara", "Ahmed"]}

@app.get("/reports")
def get_reports():
    return {"reports": ["Q1 Report", "Q2 Report"]}
