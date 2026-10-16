@echo off
cd ai-service
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
python app.py
