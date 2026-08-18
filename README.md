# Network Anomaly Detector

Batch anomaly detection prototype using Isolation Forest on synthetic network traffic, with an interactive Streamlit dashboard.

## Setup
```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```bash
python generate_sample_data.py   # creates data/sample_traffic.csv
streamlit run app.py
```

## Deploy (free, ~5 min)
1. Push this folder to a public GitHub repo
2. Go to https://share.streamlit.io → "New app"
3. Select the repo, branch `main`, main file `app.py`
4. Deploy — you'll get a public URL to put on your resume/LinkedIn

## Stack
Python · Pandas · Scikit-learn (Isolation Forest) · Streamlit · Plotly
