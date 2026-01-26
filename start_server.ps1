cd C:\AlexDev\VRAgent
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\Activate
python -B -c "import uvicorn; uvicorn.run('backend.main:app', host='0.0.0.0', port=8000)"
