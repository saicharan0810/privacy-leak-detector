import click
from analyzer.loader import APKLoader
from analyzer.tracer import Tracer
from analyzer.reporter import Reporter
import sys

@click.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('--format', '-f', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def main(apk_path, format, output):
    """
    Privacy Leak Detector for Android APKs.
    
    analyzes the APK at APK_PATH for potential privacy leaks.
    """
    print(f"Starting analysis on {apk_path}")
    
    loader = APKLoader(apk_path)
    if not loader.load():
        sys.exit(1)
        
    tracer = Tracer(loader.analysis)
    tracer.find_usages()
    tracer.analyze_reachability()
    
    results = tracer.get_results()
    
    reporter = Reporter(results)
    report_content = reporter.generate_report(format)
    
    if output:
        with open(output, 'w') as f:
            f.write(report_content)
        print(f"Report written to {output}")
    else:
        print(report_content)

if __name__ == '__main__':
    main()
