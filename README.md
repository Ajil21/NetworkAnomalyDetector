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

## Live
https://networkanomalydetector-aj.streamlit.app/

## Stack
Python · Pandas · Scikit-learn (Isolation Forest) · Streamlit · Plotly
