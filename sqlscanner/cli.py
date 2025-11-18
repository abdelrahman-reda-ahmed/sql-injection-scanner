#!/usr/bin/env python3

import argparse
import sys
import os
from .scanner import SQLInjectionScanner

def main():
    banner = """
    ███████╗ ██████╗ ██╗         ██╗███╗   ██╗██████╗ ███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
    ██╔════╝██╔═══██╗██║         ██║████╗  ██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
    ███████╗██║   ██║██║         ██║██╔██╗ ██║██║  ██║█████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
    ╚════██║██║   ██║██║         ██║██║╚██╗██║██║  ██║██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
    ███████║╚██████╔╝███████╗    ██║██║ ╚████║██████╔╝███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
    ╚══════╝ ╚═════╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
    
    SQL Injection Scanner v1.0.0
    """

    print(banner)
    
    parser = argparse.ArgumentParser(description='SQL Injection Scanner')
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests')
    parser.add_argument('-m', '--max-pages', type=int, default=50, help='Max pages to crawl')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')

    args = parser.parse_args()

    if not args.url and not args.interactive:
        parser.print_help()
        sys.exit(1)

    try:
        if args.interactive or not args.url:
            target_url = args.url
            if not target_url:
                target_url = input("Enter target URL: ").strip()
                if not target_url:
                    print("❌ No target URL provided.")
                    sys.exit(1)
            scanner = SQLInjectionScanner(target_url, args.delay, args.max_pages)
            scanner.run_interactive_mode()  # ← ALWAYS GO TO INTERACTIVE MODE
        else:
            # If URL provided but not interactive, show quick options
            scanner = SQLInjectionScanner(args.url, args.delay, args.max_pages)
            print("[*] Starting quick scan with default settings...")
            scanner.run_comprehensive_scan()
                
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()