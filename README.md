# Threat Parser

Threat Parser is a simple Python tool to extract Indicators of Compromise (IOCs) and Tactics, Techniques, and Procedures (TTPs) from threat intelligence reports.

## Features

- Extracts IOCs (such as IPs, domains, hashes) from text files.
- Extracts TTPs using MITRE ATT&CK mappings.
- Outputs results in a readable format using [Rich](https://github.com/Textualize/rich).

## Project Structure

```
main.py
parser.py
data/
    enterprise-attack.json
extractors/
    ioc_extractor.py
    ttp_extractor.py
samples/
    report.txt
    report2.txt
```

## Requirements

- Python 3.10+
- [rich](https://pypi.org/project/rich/)
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python/tree/master)
- [tldextract](https://pypi.org/project/tldextract/)

Install dependencies:
```sh
pip install rich mitreattack-python tldextract
```

## Usage

Run the parser on a sample report:
```sh
python main.py -f samples/report.txt
```

- Use `-f` or `--file` to specify the path to your report file.

## How it Works

- [`main.py`](main.py) is the entry point. It parses arguments and prints extracted IOCs and TTPs.
- [`parser.py`](parser.py) defines the [`ThreatReportParser`](parser.py) class, which loads the report and delegates extraction to:
  - [`extractors/ioc_extractor.py`](extractors/ioc_extractor.py) for IOCs
  - [`extractors/ttp_extractor.py`](extractors/ttp_extractor.py) for TTPs

## Sample Output

```
Extracted Indicators of compromise (IOCs)
-----------------------------------------
IP:
- 192.168.1.1
DOMAIN:
- example.com

Extracted Tactics, Techniques and Procedures (TTPs)
---------------------------------------------------
INITIAL ACCESS:
T1059     : Command and Scripting Interpreter         https://attack.mitre.org/techniques/T1059/
```

## License

MIT License

See python library licenses under the [LICENSES](LICENSES) directory