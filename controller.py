import redis
import json
import argparse
import sys
import os

class CrawlerController:
    def __init__(self):
        self.redis_client = redis.Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            db=0
        )
        self.queue_key = 'crawler:queue'
        self.processed_key = 'crawler:processed'
        self.results_key = 'crawler:results'
        self.config_key = 'crawler:config'
    
    def start_crawl(self, url, **kwargs):
        """Запуск краулинга"""
        self.redis_client.delete(self.queue_key)
        self.redis_client.delete(self.processed_key)
        self.redis_client.delete(self.results_key)
        
        config = {
            'url': url,
            'cookies': kwargs.get('cookies'),
            'headers': kwargs.get('headers'),
            'proxy': kwargs.get('proxy'),
            'timeout': kwargs.get('timeout', 10),
            'delay': kwargs.get('delay', 0.1),
            'concurrency': kwargs.get('concurrency', 10),
            'serialization': kwargs.get('serialization', False),
            'sleep': kwargs.get('sleep', 5),
            'exclude': kwargs.get('exclude')
        }
        self.redis_client.set(self.config_key, json.dumps(config))
        
        self.redis_client.lpush(self.queue_key, url)
        
        print(f"Started crawling: {url}")
        print("Workers will now process the queue")
    
    def get_status(self):
        queue_size = self.redis_client.llen(self.queue_key)
        processed_count = self.redis_client.scard(self.processed_key)
        results_count = self.redis_client.hlen(self.results_key)
        
        print(f"Queue size: {queue_size}")
        print(f"Processed URLs: {processed_count}")
        print(f"Results collected: {results_count}")
        
        return {
            'queue_size': queue_size,
            'processed_count': processed_count,
            'results_count': results_count
        }
    
    def get_results(self):
        results = self.redis_client.hgetall(self.results_key)
        for url, data in results.items():
            data = json.loads(data.decode('utf-8'))
            print(f"URL: {url.decode('utf-8')}")
            print(f"Status: {data.get('status')}")
            if data.get('error'):
                print(f"Error: {data.get('error')}")
            print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description='Distributed Crawler Controller')
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    start_parser = subparsers.add_parser('start', help='Start crawling')
    start_parser.add_argument('url', help='Starting URL')
    start_parser.add_argument('-C', '--cookies', help='Cookies')
    start_parser.add_argument('-H', '--headers', help='Headers')
    start_parser.add_argument('-p', '--proxy', help='Proxy')
    start_parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout')
    start_parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay')
    start_parser.add_argument('-c', '--concurrency', type=int, default=10, help='Concurrency')
    start_parser.add_argument('-s', '--serialization', action='store_true', help='Test serialization')
    start_parser.add_argument('--sleep', type=int, default=5, help='Sleep time')
    start_parser.add_argument('-e', '--exclude', help='Exclude cookies')
    
    subparsers.add_parser('status', help='Get status')
    
    subparsers.add_parser('results', help='Get results')
    
    args = parser.parse_args()
    
    controller = CrawlerController()
    
    if args.command == 'start':
        controller.start_crawl(
            args.url,
            cookies=args.cookies,
            headers=args.headers,
            proxy=args.proxy,
            timeout=args.timeout,
            delay=args.delay,
            concurrency=args.concurrency,
            serialization=args.serialization,
            sleep=args.sleep,
            exclude=args.exclude
        )
    elif args.command == 'status':
        controller.get_status()
    elif args.command == 'results':
        controller.get_results()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()