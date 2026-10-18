# 🛡️ Threat Detection Framework Based on Industrial Internet of Things (IIoT) Logs

## 📌 Project Overview

The **Threat Detection Framework Based on IIoT Logs** is a Python-based cybersecurity application designed to analyze Industrial Internet of Things (IIoT) log data and identify suspicious activities, abnormal device behavior, and potential cyber threats using rule-based detection and Machine Learning.

The application provides a web-based dashboard to upload log files, analyze events, view threat alerts, and generate reports.

## 🎯 Objectives

* Analyze IIoT log data to identify suspicious activities.
* Detect repeated failed login attempts.
* Identify unusually high network traffic.
* Detect abnormal device behavior.
* Apply Machine Learning for anomaly detection.
* Store logs and alerts securely in an SQLite database.
* Generate reports to support security analysis.

## 🚀 Key Features

* **Dashboard:** Displays total logs, normal events, suspicious events, and high-risk alerts.
* **CSV Log Upload:** Upload and analyze IIoT log files.
* **Rule-Based Detection:** Identifies suspicious login attempts, abnormal traffic, and unusual connections.
* **Machine Learning:** Uses the Isolation Forest algorithm to detect unusual patterns.
* **Threat Classification:** Categorizes alerts as Low, Medium, High, or Critical.
* **Database Management:** Stores analyzed logs and threat alerts in SQLite.
* **Threat Monitoring:** Displays detected threats and suspicious events.
* **Reports and Charts:** Visualizes threat statistics and detection results.
* **CSV Export:** Exports suspicious logs for further investigation.
* **Input Validation:** Validates uploaded files and required log fields.

## 🛠️ Technologies Used

| Technology            | Purpose                            |
| --------------------- | ---------------------------------- |
| Python 3              | Core programming language          |
| Flask                 | Web application framework          |
| Pandas                | Log processing and analysis        |
| Scikit-learn          | Machine Learning anomaly detection |
| Isolation Forest      | Identifies unusual log patterns    |
| SQLite                | Database storage                   |
| HTML                  | Webpage structure                  |
| CSS                   | Styling and responsive design      |
| JavaScript            | Frontend interactions and charts   |
| Matplotlib / Chart.js | Data visualization                 |

## 📂 Project Structure

```text
iiot-threat-detection/
│
├── app.py
├── detection.py
├── database.py
├── requirements.txt
├── sample_logs.csv
├── README.md
│
├── templates/
│   ├── index.html
│   ├── upload.html
│   ├── logs.html
│   ├── threats.html
│   └── reports.html
│
├── static/
│   ├── style.css
│   └── dashboard.js
│
└── tests/
    └── test_detection.py
```

## 🔍 Threat Detection Methods

### 1. Repeated Failed Login Detection

Identifies log records containing multiple failed login attempts that may indicate a brute-force login attempt.

### 2. Abnormal Network Traffic Detection

Flags unusually high network traffic that may indicate unexpected device activity or possible data transfer anomalies.

### 3. Suspicious Connection Detection

Examines source IP addresses, event types, and connection patterns to identify potentially suspicious events.

### 4. Machine Learning Detection

Uses the Isolation Forest algorithm from Scikit-learn to identify unusual patterns in numerical log features.

### 5. Threat Severity Classification

Assigns severity levels based on the implemented detection rules and anomaly results:

* **Low:** Minor unusual activity.
* **Medium:** Suspicious activity requiring review.
* **High:** Significant suspicious behavior.
* **Critical:** High-priority events requiring immediate investigation.

*Severity depends on the application's detection rules and should not be treated as confirmation of an attack.*

## 📊 Sample Dataset

The project uses a synthetic dataset named `sample_logs.csv`.

The dataset contains the following columns:

| Column          | Description                     |
| --------------- | ------------------------------- |
| timestamp       | Date and time of the event      |
| device_id       | Identifier of the IIoT device   |
| source_ip       | Source IP address               |
| event_type      | Type of recorded event          |
| failed_logins   | Number of failed login attempts |
| network_traffic | Network traffic measurement     |
| status          | Event status                    |

The sample data includes normal device activity, repeated failed logins, unusual traffic levels, and suspicious connection events.

## ⚙️ Installation and Setup

### Prerequisites

* Python 3 installed on your computer.
* Git installed on your computer.
* A code editor such as Visual Studio Code.

### Step 1: Clone the Repository

```bash
git clone https://github.com/poodisuresh-078/iiot-threat-detection.git
```

### Step 2: Open the Project Folder

```bash
cd iiot-threat-detection
```

### Step 3: Create a Virtual Environment

```bash
python -m venv venv
```

### Step 4: Activate the Virtual Environment

For Windows:

```bash
venv\Scripts\activate
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Run the Application

```bash
python app.py
```

### Step 7: Open the Application

Open your browser and visit:

**http://127.0.0.1:5000**

The Flask application should display the dashboard if it starts successfully.

## 🧪 Testing

Run the unit tests using:

```bash
python -m unittest discover -s tests
```

The tests should verify the detection module's behavior, including its handling of normal and suspicious log records.

## 📈 Expected Results

After uploading a valid CSV file, the application can display:

* Total logs analyzed.
* Number of normal events.
* Number of suspicious events.
* High-risk alerts.
* Detected anomalies and their severity.
* Threat statistics and charts.
* Downloadable suspicious-log reports.

Actual results depend on the uploaded dataset and the implemented detection logic.

## 🔐 Security Considerations

* Validate uploaded file types and required CSV columns.
* Limit upload sizes.
* Use parameterized SQL queries.
* Handle invalid input and processing errors.
* Use synthetic data for demonstrations and testing.
* Avoid exposing sensitive log information.
* Investigate alerts before taking security-related action.

## 🔮 Future Enhancements

* Real-time IIoT log monitoring.
* Advanced anomaly detection models.
* Email notifications for critical alerts.
* Improved threat visualization.
* Device-specific behavioral analysis.
* Integration with security monitoring systems.

## 👨‍💻 Author

**Poodi Suresh Reddy**

GitHub: [poodisuresh-078](https://github.com/poodisuresh-078)

## 🎓 Project Type

Academic Project | Python Full Stack Development | Cybersecurity | Machine Learning

## ⚠️ Disclaimer

This project is intended for educational and research purposes. It uses synthetic IIoT log data. Detected anomalies indicate potential threats and require further investigation; they do not confirm actual cyberattacks.


