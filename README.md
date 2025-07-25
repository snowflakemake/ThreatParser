# Threat Parser

Threat Parser is a simple Python tool to extract Indicators of Compromise (IOCs) and Tactics, Techniques, and Procedures (TTPs) from threat intelligence reports. It can also guess possible adversaries based on the extracted TTPs using MITRE ATT&CK mappings.

This tool is designed to help analysts quickly identify key information from threat reports, making it easier to understand the threats and potential adversaries involved. Please note that this is a work in progress and may not cover all edge cases or formats of threat reports. Be aware of potential false positives or negatives in the extraction process.

The tool uses the [MITRE ATT&CK](https://attack.mitre.org/) framework to map TTPs and identify potential adversaries based on the techniques observed in the reports. It also supports VirusTotal hash lookups to provide additional context for extracted IOCs.

The TTPs and IOCs are extracted using regular expressions and string matching techniques, and the results are displayed in a user-friendly format.

## Features

- Extracts IOCs (such as IPs, domains, hashes) from text files.
- Extracts TTPs using MITRE ATT&CK mappings.
- Outputs results in a readable format using [Rich](https://github.com/Textualize/rich).

## Project Structure

```
main.py
parser.py
export.py
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
- [python-dotenv](https://pypi.org/project/python-dotenv/)
- [rich](https://pypi.org/project/rich/)
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python/tree/master)
- [tldextract](https://pypi.org/project/tldextract/)

Install dependencies:
```sh
pip install rich mitreattack-python tldextract python-dotenv
```

## Usage

Run the parser on a sample report:
```sh
python main.py -f samples/report.txt
```

- Use `-f` or `--file` to specify the path to your report file.
- Use `-a` or `--attribute` to edit how many estimated adversaries to be shown (default 5).
- Use `-n` or `--no-lookup` to disable VirusTotal hash lookups.
- Use `-o` or `--output` to specify an output file for the extracted IOCs and TTPs.

> [!NOTE]
> For now, only csv output is supported.

To send found hashes to VirusTotal, set the `VT_API_KEY` in a `.env` file:
```
VT_API_KEY=your_virustotal_api_key
```

> [!NOTE]
> The VirusTotal API key is optional. If not provided, hash lookups will be skipped.

## How it Works

- [`main.py`](main.py) is the entry point. It parses arguments and prints extracted IOCs and TTPs.
- [`parser.py`](parser.py) defines the [`ThreatReportParser`](parser.py) class, which loads the report and delegates extraction to:
  - [`extractors/ioc_extractor.py`](extractors/ioc_extractor.py) for IOCs
  - [`extractors/ttp_extractor.py`](extractors/ttp_extractor.py) for TTPs
  - [`extractors/group_extractor.py`](extractors/group_extractor.py) for possible adversaries based on TTPs
- [`export.py`](export.py) handles exporting results to CSV.

## Sample Output

![image](assets/example_output.png)

## License

MIT License

See python library licenses under the [LICENSES](LICENSES) directory