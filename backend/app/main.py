from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# ENABLE CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HOME ROUTE
@app.get("/")
def home():
    return {
        "message": "ForensiAI Backend Running"
    }

# ANALYZE ROUTE
@app.post("/analyze")
async def analyze_evidence(
    evidence: str = Form(""),
    file: UploadFile = File(None)
):

    try:

        text_output = ""

        # HANDLE TEXT INPUT
        if evidence:
            text_output += evidence + "\n"

        # HANDLE FILE INPUT
        if file:

            file_bytes = await file.read()

            try:
                file_text = file_bytes.decode("utf-8")
            except:
                file_text = str(file_bytes)

            text_output += file_text

        # MOCK FORENSIC REPORT
        mock_report = f"""
DIGITAL FORENSIC INVESTIGATION REPORT

SUMMARY:
Potential cyber intrusion activity detected.

INDICATORS OF COMPROMISE:
- Suspicious authentication attempts
- Unauthorized access patterns
- Possible malicious indicators

RISK LEVEL:
HIGH

RECOMMENDED ACTIONS:
- Isolate affected systems
- Investigate firewall activity
- Enable MFA
- Review system logs
- Conduct forensic acquisition

EVIDENCE PREVIEW:
{text_output[:1500]}
"""

        return {
            "analysis": mock_report
        }

    except Exception as e:

        return {
            "analysis": f"BACKEND ERROR: {str(e)}"
        }