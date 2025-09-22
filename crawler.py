import argparse
import requests
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs
import re
from collections import deque
import time
import sys
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set
import concurrent.futures
import threading
import pickle
import base64
import hashlib
import redis
import json
import os

# Redis connection pool
redis_pool = None

def get_redis_connection():
    global redis_pool
    if redis_pool is None:
        redis_host = os.getenv('REDIS_HOST', 'redis')
        redis_port = int(os.getenv('REDIS_PORT', 6379))
        redis_pool = redis.ConnectionPool(host=redis_host, port=redis_port, db=0)
    return redis.Redis(connection_pool=redis_pool)

class TreeNode:
    def __init__(self, name):
        self.name = name
        self.children = {}
        self.is_endpoint = False

class URLTree:
    def __init__(self):
        self.root = TreeNode("")
    
    def add_url(self, url):
        parsed = urlparse(url)
        path = parsed.path
        
        clean_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            '',
            '',
            ''
        ))
        
        parts = [part for part in path.split('/') if part]
        if not parts:
            parts = ['']
        
        current = self.root
        
        for part in parts:
            if part not in current.children:
                current.children[part] = TreeNode(part)
            current = current.children[part]
        
        if not current.is_endpoint:
            current.is_endpoint = True
            return True, clean_url
        
        return False, clean_url
    
    def print_tree(self, node=None, level=0, prefix=""):
        if node is None:
            node = self.root
        
        indent = "  " * level
        if level > 0:
            print(f"{indent}{prefix}{node.name}{'/' if node.children else ''}")
        
        for child_name, child_node in node.children.items():
            self.print_tree(child_node, level + 1, "/")
    
    def get_all_urls(self, base_url):
        urls = []
        
        def traverse(node, current_path, base_domain):
            if node.is_endpoint:
                full_path = '/'.join(current_path)
                if not full_path.startswith('/'):
                    full_path = '/' + full_path
                url = f"{base_domain}{full_path}"
                urls.append(url)
            
            for child_name, child_node in node.children.items():
                new_path = current_path + [child_name]
                traverse(child_node, new_path, base_domain)
        
        parsed_base = urlparse(base_url)
        base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        traverse(self.root, [], base_domain)
        return urls

def extract_urls_from_html(html_content, base_url):
    url_pattern = r'(?:href|src)=["\']([^"\']+)["\']'
    urls = re.findall(url_pattern, html_content, re.IGNORECASE)
    
    local_urls = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.netloc:
            full_url = urljoin(base_url, url)
            local_urls.append(full_url)
        elif parsed.netloc in base_url:
            local_urls.append(url)
    
    return local_urls

def generate_pickle_payload(sleep_time=5):
    class SleepPayload:
        def __reduce__(self):
            import time
            return (time.sleep, (sleep_time,))
    
    payload = pickle.dumps(SleepPayload())
    return base64.b64encode(payload).decode('utf-8')[1:-1]

def generate_php_payload(sleep_time=5):
    payload = f'O:8:"stdClass":1:{{s:4:"sleep";s:{len(str(sleep_time))}:"{sleep_time}";}}'
    return base64.b64encode(payload.encode('utf-8')).decode('utf-8')

async def test_serialization_vulnerability(session, url, cookies, headers, timeout, sleep_time, exclude_cookies):
    vulnerabilities = []
    
    pickle_cookies = cookies.copy() if cookies else {}
    php_cookies = cookies.copy() if cookies else {}
    
    for cookie_name in pickle_cookies:
        if cookie_name not in exclude_cookies:
            pickle_cookies[cookie_name] = generate_pickle_payload(sleep_time)
    
    for cookie_name in php_cookies:
        if cookie_name not in exclude_cookies:
            php_cookies[cookie_name] = generate_php_payload(sleep_time)

    try:
        start_time = time.time()
        async with session.get(
            url,
            headers=headers,
            cookies=pickle_cookies,
            timeout=aiohttp.ClientTimeout(total=timeout + sleep_time + 2),
            ssl=False,
            allow_redirects=False
        ) as response:
            response_time = time.time() - start_time
            
            if abs(response_time - sleep_time) < 1.0:
                vulnerabilities.append(("pickle", response_time))
                print(f"  Potential pickle serialization vulnerability detected! Response time: {response_time:.2f}s")
    
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    
    try:
        start_time = time.time()
        async with session.get(
            url,
            headers=headers,
            cookies=php_cookies,
            timeout=aiohttp.ClientTimeout(total=timeout + sleep_time + 2),
            ssl=False,
            allow_redirects=False
        ) as response:
            response_time = time.time() - start_time
            
            if abs(response_time - sleep_time) < 1.0:
                vulnerabilities.append(("php", response_time))
                print(f"  Potential PHP serialization vulnerability detected! Response time: {response_time:.2f}s")
    
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    
    return vulnerabilities

async def fetch_url_async(session, url, cookies=None, headers=None, timeout=10, 
                         test_serialization=False, sleep_time=5, exclude_cookies=None,
                         is_new_directory=False, stored_cookies=None):
    results = {}
    vulnerabilities = []
    
    current_cookies = stored_cookies if is_new_directory and stored_cookies else cookies
    
    for scheme in ['http', 'https']:
        try:
            parsed_url = urlparse(url)
            target_url = urlunparse((scheme, parsed_url.netloc, parsed_url.path, 
                                   parsed_url.params, parsed_url.query, parsed_url.fragment))
            
            request_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            if headers:
                request_headers.update(headers)
            
            print(f"Trying {scheme.upper()} request to: {target_url}")
            
            async with session.get(
                target_url,
                headers=request_headers,
                cookies=current_cookies,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False,
                allow_redirects=True
            ) as response:
                response.raise_for_status()
                
                response_cookies = {}
                for cookie_name, morsel in response.cookies.items():
                    response_cookies[cookie_name] = morsel.value
                
                try:
                    content = await response.text(encoding='utf-8')
                except UnicodeDecodeError:
                    try:
                        content = await response.text(encoding='cp1251')
                    except:
                        content_bytes = await response.read()
                        content = content_bytes.decode('utf-8', errors='ignore')
                
                results[scheme] = {
                    'content': content,
                    'status_code': response.status,
                    'final_url': str(response.url),
                    'cookies': response_cookies
                }
                print(f"  Success: status {response.status}")
                
                if is_new_directory:
                    print(f"  Testing serialization vulnerabilities...")
                    vulns = await test_serialization_vulnerability(
                        session, target_url, response_cookies | current_cookies, headers, 
                        timeout, sleep_time, exclude_cookies or []
                    )
                    vulnerabilities.extend(vulns)
            
        except (aiohttp.ClientError, asyncio.TimeoutError):
            results[scheme] = None
    
    return results, vulnerabilities

def parse_cookies(cookie_string):
    if not cookie_string:
        return None
    
    cookies = {}
    for cookie in cookie_string.split(';'):
        cookie = cookie.strip()
        if '=' in cookie:
            key, value = cookie.split('=', 1)
            cookies[key.strip()] = value.strip()
    
    return cookies

def parse_headers(header_string):
    if not header_string:
        return None
    
    headers = {}
    if '\\n' in header_string:
        header_lines = header_string.split('\\n')
    else:
        header_lines = header_string.splitlines()
    
    for header_line in header_lines:
        header_line = header_line.strip()
        if header_line and ':' in header_line:
            key, value = header_line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    return headers

def parse_proxy(proxy_string):
    if not proxy_string:
        return None
    
    if not proxy_string.startswith(('http://', 'https://', 'socks5://')):
        proxy_string = 'http://' + proxy_string
    
    return proxy_string

def parse_exclude_cookies(exclude_string):
    if not exclude_string:
        return []
    
    return [cookie.strip() for cookie in exclude_string.split(',')]

def print_help():
    help_text = """
Website URL Crawler - Website crawling and URL tree building tool

Usage:
  python crawler.py [OPTIONS] URL

Options:
  -h, --help            Show this help message
  -C COOKIES, --cookies COOKIES
                        Cookies in format "name1=value1;name2=value2"
  -H HEADERS, --headers HEADERS
                        Headers in format "Header1: value1\\nHeader2: value2"
  -p PROXY, --proxy PROXY
                        Proxy in format ip:port or protocol://user:pass@ip:port
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
  -d DELAY, --delay DELAY
                        Delay between requests in seconds (default: 0.1)
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent requests (default: 10)
  -s, --serialization   Test deserialization vulnerabilities
  --sleep SLEEP         Sleep time for payloads (default: 5)
  -e EXCLUDE, --exclude EXCLUDE
                        Cookies to exclude (comma separated)

Examples:
  python crawler.py https://example.com
  python crawler.py -C "session=abc123;user=john" -H "Authorization: Bearer token" example.com
  python crawler.py -p 127.0.0.1:8080 -t 15 https://example.com
  python crawler.py -p http://user:pass@127.0.0.1:8080 https://example.com
  python crawler.py -s --sleep 3 -e "PHPSESSID,session_id" https://example.com
"""
    print(help_text)

class DirectoryTracker:
    def __init__(self):
        self.visited_directories = set()
        self.directory_cookies = {}
    
    def get_directory_key(self, url):
        parsed = urlparse(url)
        path = parsed.path
        
        if '/' in path:
            directory = path.rsplit('/', 1)[0]
            if not directory:
                directory = '/'
            return f"{parsed.netloc}{directory}"
        return f"{parsed.netloc}/"
    
    def is_new_directory(self, url):
        directory_key = self.get_directory_key(url)
        is_new = directory_key not in self.visited_directories
        return is_new, directory_key
    
    def mark_directory_visited(self, directory_key):
        self.visited_directories.add(directory_key)
    
    def store_cookies(self, directory_key, cookies):
        if cookies:
            self.directory_cookies[directory_key] = cookies
    
    def get_cookies(self, directory_key):
        return self.directory_cookies.get(directory_key)

async def process_queue(session, queue, processed_urls, url_tree, cookies, headers, 
                       timeout, delay, concurrency, test_serialization, sleep_time, 
                       exclude_cookies):
    semaphore = asyncio.Semaphore(concurrency)
    directory_tracker = DirectoryTracker()
    
    async def process_url(url):
        async with semaphore:
            with threading.Lock():
                if url in processed_urls:
                    return
                processed_urls.add(url)
            
            print(f"\nProcessing: {url}")
            
            is_new_directory, directory_key = directory_tracker.is_new_directory(url)
            stored_cookies = directory_tracker.get_cookies(directory_key)
            
            results, vulnerabilities = await fetch_url_async(
                session, url, cookies, headers, timeout, 
                test_serialization, sleep_time, exclude_cookies,
                is_new_directory, stored_cookies
            )
            
            if is_new_directory:
                directory_tracker.mark_directory_visited(directory_key)
                for scheme in ['https', 'http']:
                    if results.get(scheme) and results[scheme].get('cookies'):
                        directory_tracker.store_cookies(directory_key, results[scheme]['cookies'])
                        print(f"  Saved cookies for directory {directory_key}")
                        break
            
            content = None
            for scheme in ['https', 'http']:
                if results.get(scheme) and results[scheme].get('content'):
                    content = results[scheme]['content']
                    print(f"Using content from {scheme.upper()} request")
                    break
            
            if not content:
                print("Failed to get content from both protocols")
                return
            
            new_urls = extract_urls_from_html(content, url)
            
            with threading.Lock():
                for new_url in new_urls:
                    is_new, clean_url = url_tree.add_url(new_url)
                    if is_new and clean_url not in processed_urls and clean_url not in queue:
                        queue.append(clean_url)
                        print(f"  Added to queue: {clean_url}")
            
            await asyncio.sleep(delay)
    
    while queue:
        tasks = []
        current_batch = list(queue)
        queue.clear()
        
        for url in current_batch:
            tasks.append(asyncio.create_task(process_url(url)))
        
        await asyncio.gather(*tasks)
        
        if not queue:
            break

async def main_async():
    parser = argparse.ArgumentParser(description='Crawl website and build URL tree', add_help=False)
    parser.add_argument('url', nargs='?', help='Starting URL')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    parser.add_argument('-C', '--cookies', help='Cookies in format "name1=value1;name2=value2"')
    parser.add_argument('-H', '--headers', help='Headers in format "Header1: value1\\nHeader2: value2"')
    parser.add_argument('-p', '--proxy', help='Proxy in format ip:port or protocol://user:pass@ip:port')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between requests in seconds')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Number of concurrent requests')
    parser.add_argument('-s', '--serialization', action='store_true', help='Test deserialization vulnerabilities')
    parser.add_argument('--sleep', type=int, default=5, help='Sleep time for payloads')
    parser.add_argument('-e', '--exclude', help='Cookies to exclude (comma separated)')
    
    args = parser.parse_args()
    
    if args.help or not args.url:
        print_help()
        sys.exit(0)
    
    cookies = parse_cookies(args.cookies)
    headers = parse_headers(args.headers)
    proxy_url = parse_proxy(args.proxy)
    exclude_cookies = parse_exclude_cookies(args.exclude)
    
    print("Script settings:")
    print(f"  URL: {args.url}")
    print(f"  Cookies: {cookies}")
    print(f"  Headers: {headers}")
    print(f"  Proxy: {proxy_url}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Delay: {args.delay}s")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Serialization test: {args.serialization}")
    if args.serialization:
        print(f"  Sleep time: {args.sleep}s")
        print(f"  Excluded cookies: {exclude_cookies}")
    print("-" * 50)
    
    start_url = args.url
    if not start_url.startswith(('http://', 'https://')):
        start_url = 'https://' + start_url
    
    url_tree = URLTree()
    queue = deque([start_url])
    processed_urls = set()
    
    print(f"Starting crawl from: {start_url}")
    
    connector = aiohttp.TCPConnector(ssl=False, limit=args.concurrency)
    
    proxy_auth = None
    if proxy_url:
        parsed_proxy = urlparse(proxy_url)
        if parsed_proxy.username and parsed_proxy.password:
            proxy_auth = aiohttp.BasicAuth(parsed_proxy.username, parsed_proxy.password)
            proxy_url = f"{parsed_proxy.scheme}://{parsed_proxy.hostname}:{parsed_proxy.port}"
    
    session_kwargs = {
        'connector': connector,
        'trust_env': False
    }
    
    if proxy_url:
        session_kwargs['proxy'] = proxy_url
        if proxy_auth:
            session_kwargs['proxy_auth'] = proxy_auth
    
    async with aiohttp.ClientSession(**session_kwargs) as session:
        if proxy_url:
            print(f"Using proxy: {proxy_url}")
            if proxy_auth:
                print(f"With auth: {proxy_auth.login}")
        
        await process_queue(session, queue, processed_urls, url_tree, cookies, 
                           headers, args.timeout, args.delay, args.concurrency,
                           args.serialization, args.sleep, exclude_cookies)
    
    print("\n" + "="*50)
    print("CRAWL COMPLETED")
    print("="*50)
    
    print("\nAll found URLs:")
    all_urls = url_tree.get_all_urls(start_url)
    for url in sorted(all_urls):
        print(f"  {url}")
    
    print(f"\nTree structure (found {len(all_urls)} URLs):")
    url_tree.print_tree()

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    asyncio.run(main_async())

if __name__ == "__main__":
    main()