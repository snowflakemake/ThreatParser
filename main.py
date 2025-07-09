from rich.console import Console
from parser import ThreatReportParser
import argparse
console = Console()

def main():    
    parser = argparse.ArgumentParser(prog='Threat Parser', description='A simple program to extract IOCs and TTPs from a text file')
    parser.add_argument('-f', '--file', default='samples/report.txt')
    parser.add_argument('--no-lookup', action='store_false', dest='lookup',
                        help='Disable VirusTotal hash lookup. Useful if you do not have a VT API key')

    args = parser.parse_args()

    report_path = args.file
    parser = ThreatReportParser(report_path)
    try:
        iocs = parser.extract_iocs(console, lookup=args.lookup)
        ttps = parser.extract_ttps(console)
    except Exception as e:
        console.print_exception()
        exit(1)

    console.rule("[bold green]Extracted Indicators of compromise (IOCs)[/bold green]")
    seen = set()
    for ioc in iocs:
        if ioc['type'] not in seen:
            if not len(seen) == 0:
                console.line()
            seen.add(ioc['type'])
            console.print(f"[bold yellow]{ioc['type'].upper()}[/bold yellow]:")

        if 'lookup' in ioc:
            console.print(f"{ioc['value']:<35}: [bold cyan]{ioc['lookup']}[/bold cyan]")
        else:
            console.print(f"[bold white]- {ioc['value']}[/bold white]")

    seen = set()
    console.line()
    console.rule("[bold blue]Extracted Tactics, Techniques and Procedures (TTPs)[/bold blue]")
    for ttp in ttps:
        if ttp['phase'] not in seen:
            if not len(seen) == 0:
                console.line()
            seen.add(ttp['phase'])
            console.print(f"[bold yellow]{ttp['phase'].upper()}[/bold yellow]:")

        console.print(f"[bold cyan]{ttp['value']:<10}[/bold cyan]: {ttp['name']:<50}{ttp['ref']}")
    

if __name__ == "__main__":
    main()