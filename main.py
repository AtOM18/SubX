import argparse
from colorama import Fore, Style, init
from dotenv import load_dotenv

from subdomain_enum import enum

# Initialize colorama
init(autoreset=True)

# Load environment variables from .env file
load_dotenv()

banner = f"""
{Fore.CYAN},d88~~\\  888   |  888~~\\   Y88b    / 
{Fore.CYAN}8888     888   |  888   |   Y88b  /  
{Fore.CYAN}`Y88b    888   |  888 _/     Y88b/   
{Fore.CYAN} `Y88b,  888   |  888  \\     /Y88b   
{Fore.CYAN}   8888  Y88   |  888   |   /  Y88b  
{Fore.CYAN}\\__88P'   "8__/   888__/   /    Y88b   {Fore.YELLOW}v1.0
"""

success = f"[{Fore.GREEN}✓{Style.RESET_ALL}] "

def args():
    parser = argparse.ArgumentParser(usage="python3 subx.py [domain]",
                                     description="Passive subdomain enumeration tool for bug-bounty hunters & penetration testers.")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-V', '--verbose', action='store_true', help='Show verbose API progress')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for each API request in seconds (default: 10)')
    parser.add_argument('domain', metavar='[domain]', action='store', help='specifies the target domain')
    parser.add_argument("-o", "--output", action="store", dest="output", help="Specifies the output file.")
    return parser.parse_args()

if __name__ == "__main__":
    print(banner)
    arguments = args()
    print(success + "Target domain: " + Fore.GREEN + arguments.domain + Style.RESET_ALL + "\n")
    enum(
        arguments.domain,
        arguments.output,
        verbose=arguments.verbose,
        threads=arguments.threads,
        timeout=arguments.timeout
    )