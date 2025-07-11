from rich.console import Console
from parser import ThreatReportParser
import export
import argparse
console = Console()

def main():    
    parser = argparse.ArgumentParser(prog='Threat Parser', description='A simple program to extract IOCs and TTPs from a text file')
    parser.add_argument('-f', '--file', default='samples/report.txt')
    parser.add_argument('-n', '--no-lookup', action='store_false', dest='lookup',
                        help='Disable VirusTotal hash lookup. Useful if you do not have a VT API key')
    parser.add_argument('-o', '--output', help='Output file to save the extracted IOCs and TTPs')
    parser.add_argument('-a', '--attribute', default=5, help='Guess adversaries from TTPs', type=int)

    args = parser.parse_args()

    report_path = args.file
    parser = ThreatReportParser(report_path, console)
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

        if 'name' in ioc:
            console.print(f"{ioc['value']:<35}: [bold cyan]{ioc['name']}[/bold cyan]")
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
    
    if args.attribute > 0:
        console.line()
        try:
            with console.status("[bold yellow]Guessing possible adversaries from TTPs...", spinner="dots"):
                groups = parser.extract_possible_groups(console, ttps, numbers_of_groups=args.attribute)
            console.rule("[bold magenta]Possible adversaries from TTPs[/bold magenta]")
            if not groups:
                console.print("[bold red]No groups matched the observed TTPs[/bold red]")
            else:
                for group, data in groups:
                    console.print(f"[bold yellow]{group+':':<20}[/bold yellow] {data['match_count']:>5}/{int(round(data['match_count']/data['probability'], 0))} matches | Probability: {data['probability']}")
        except Exception as e:
            console.print_exception()
            exit(1)

    if args.output:
        console.line()
        with console.status("[bold green]Exporting to CSV...[/bold green]", spinner="dots"):
            export.export_to_csv([iocs, ttps], args.output, 2)
        
        console.print(f"[bold green]Exported to {args.output}[/bold green]")

if __name__ == "__main__":
    main()