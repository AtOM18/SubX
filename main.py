import argparse
from colorama import Fore, Style, init
from dotenv import load_dotenv

from subdomain_enum import enum
from subdomain_probe import probe_mode  # <-- Import the new probe module

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
{Fore.CYAN}\\__88P'   "8__/   888__/   /    Y88b   {Fore.YELLOW}v1.1
"""

success = f"[{Fore.GREEN}✓{Style.RESET_ALL}] "

def args():
    parser = argparse.ArgumentParser(
        usage="python3 subx.py [options] [domain]",
        description="Passive subdomain enumeration tool for bug-bounty hunters & penetration testers."
    )
    parser.add_argument('-V', '--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose API progress')
    parser.add_argument('-t','--threads', type=int, default=20, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for each API request in seconds (default: 10)')
    parser.add_argument('-o', '--output', action='store', dest='output', help='Specifies the output file.')
    parser.add_argument('-m', '--mode', type=int, default=0, help='Mode: 0 = subdomain enumeration (default), 1 = subdomain enumeration + live probe')
    parser.add_argument('domain', metavar='[domain]', nargs='?', help='Specifies the target domain')
    return parser.parse_args()

if __name__ == "__main__":
    print(banner)
    arguments = args()

    if arguments.mode == 0:
        if not arguments.domain:
            print(f"{Fore.RED}Error: Please specify a domain for subdomain enumeration.{Style.RESET_ALL}")
            print("Use -h for help.")
        else:
            print(success + "Target domain: " + Fore.GREEN + arguments.domain + Style.RESET_ALL + "\n")
            enum(
                arguments.domain,
                arguments.output,
                verbose=arguments.verbose,
                threads=arguments.threads,
                timeout=arguments.timeout
            )
    elif arguments.mode == 1:
        if not arguments.domain:
            print(f"{Fore.RED}Error: Please specify a domain for subdomain enumeration.{Style.RESET_ALL}")
            print("Use -h for help.")
        else:
            probe_mode(
                arguments.domain,
                arguments.output,
                arguments.verbose,
                arguments.threads,
                arguments.timeout,
                enum
            )
    else:
        print(f"{Fore.RED}Error: Unsupported mode selected. Only mode 0 (subdomain enumeration) and mode 1 (subdomain enumeration + live probe) are implemented.{Style.RESET_ALL}")