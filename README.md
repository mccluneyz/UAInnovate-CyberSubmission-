UAInnovate-CyberSubmission – SOC Attack Narrative Dashboard
===========================================================

What this is
------------

A lightweight web-based dashboard that helps a SOC analyst take raw security event data and understand a potential coordinated attack in **30 seconds or less**.

- **Backend**: Node.js + Express (`server.js`) with a single `/api/analyze` endpoint.
- **Frontend**: Static HTML/CSS/JS in `public/`, served by the backend.
- **Input**: Security events in **CSV (Excel-compatible)** format.
- **Output**: A visual “attack story”: key indicators, suspected campaigns, and a time-ordered event view.

Running it locally
------------------

1. Install Node.js (which also installs `npm`) from the official site.
2. In a terminal, from this project directory:

   ```bash
   npm install
   npm start
   ```

3. Open `http://localhost:3000` in a browser.

Uploading CSV log data
----------------------

1. Prepare a CSV file (you can create it directly in Excel and save as CSV).
2. The first row should be column headers. Recommended headers:

   - `timestamp` – ISO timestamp (e.g. `2026-02-28T12:00:01Z`)
   - `type` – log type: `auth`, `firewall`, `dns`, `malware`, etc.
   - `severity` – e.g. `low`, `medium`, `high`, `critical`
   - `source_ip`
   - `dest_ip`
   - `username`
   - `action` – e.g. `failed`, `success`, `allowed`, `blocked`, `detected`
   - `message` – free-text description of the event

3. On the dashboard page:

   - Use the file input to select your `.csv` file.
   - Click **Analyze Logs**.

The browser parses the CSV into JSON events and sends them to the backend, which:

- Normalizes fields (accepts common variants like `src_ip`, `destination_ip`, `@timestamp`, `level`, etc.).
- Detects:
  - Brute-force/login spray patterns and possible account takeover.
  - Multi-step campaigns from the same source within a short time window (firewall + DNS + malware, etc.).
- Returns:
  - **Summary cards** for total volume, time window, top severity, and highest campaign score.
  - **Key indicators** (with scores and explanations).
  - **Suspected campaigns** (source IP, users touched, severity, and score).
  - **Event timeline** to quickly scan what happened and when.

Sample data
-----------

The `public/sample-logs.csv` file contains a simple synthetic scenario:

- Multiple failed logins for one user from a single IP.
- A later successful login.
- Follow-on firewall, DNS, and malware events from the same source.

You can upload this sample CSV in the UI to see how the dashboard presents a coordinated attack narrative.

Deploying / hosting
-------------------

To make this dashboard accessible via a URL, you can:

- Deploy the Node.js app to a service such as Render, Railway, Fly.io, Azure App Service, or similar.
- Or run it behind an existing web server / reverse proxy (e.g. Nginx) that exposes `http://your-domain/...` to the outside world and forwards traffic to the Node.js process.

The only requirement for the app is that the Node environment can run `node server.js` and accept HTTP traffic on the configured port.
