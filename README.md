
# LogSleuth 🔎

A lightweight Python command-line tool that analyzes sample
authentication logs and flags IP addresses with repeated
failed-login attempts.

## Features

- Parses log files line by line.
- Counts failed login attempts by IP address.
- Configurable alert threshold.
- Displays a readable security report.
- Uses Python's standard library only.

## Requirements

Python 3.9 or newer.

## Run

```bash
python3 main.py
```

Change the alert threshold:

```bash
python3 main.py --threshold 2
```

Analyze another log file:

```bash
python3 main.py path/to/your.log --threshold 5
```

## Limitations

This is an educational prototype using a simple log pattern.
It does not confirm malicious activity, block IP addresses,
or provide real-time monitoring.

## Future improvements

- Add automated unit tests.
- Export reports as JSON or CSV.
- Build a Streamlit dashboard.
- Add support for additional log formats.
- Evaluate detection accuracy on labeled test data.

## Technologies

Python, regular expressions, pathlib, argparse, collections.
