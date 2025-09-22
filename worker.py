import redis
import json
import os
import asyncio
import aiohttp
from urllib.parse import urlparse
import time

class DistributedCrawler:
    def __init__(self):
        self.redis_client = redis.Redis(
            host=os.getenv('REDIS_HOST', 'redis-service'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            db=0,
            decode_responses=True
        )
        self.queue_key = 'crawler:queue'
        self.processed_key = 'crawler:processed'
        self.results_key = 'crawler:results'
        self.config_key = 'crawler:config'
    
    async def fetch_url(self, session, url, timeout=10):
        """Простой fetch URL"""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                content = await response.text()
                return {
                    'url': url,
                    'status': response.status,
                    'content': content[:500],  # Сохраняем только часть контента
                    'success': True
                }
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e),
                'success': False
            }
    
    def extract_urls(self, content, base_url):
        """Простая экстракция URL из HTML"""
        import re
        pattern = r'href=["\']([^"\']+)["\']'
        urls = re.findall(pattern, content)
        
        full_urls = []
        for url in urls:
            if url.startswith(('http://', 'https://')):
                full_urls.append(url)
            else:
                full_urls.append(f"{base_url.rstrip('/')}/{url.lstrip('/')}")
        
        return full_urls
    
    async def process_url(self, url):
        """Обработка URL воркером"""
        # Получаем конфигурацию
        config_data = self.redis_client.get(self.config_key)
        if not config_data:
            print("No configuration found")
            return
        
        config = json.loads(config_data)
        timeout = config.get('timeout', 10)
        
        connector = aiohttp.TCPConnector(ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Обрабатываем URL
            result = await self.fetch_url(session, url, timeout)
            
            if result['success']:
                # Извлекаем новые URL
                new_urls = self.extract_urls(result['content'], url)
                
                # Добавляем новые URL в очередь
                for new_url in new_urls:
                    if not self.redis_client.sismember(self.processed_key, new_url):
                        self.redis_client.lpush(self.queue_key, new_url)
                        print(f"Added to queue: {new_url}")
                
                # Сохраняем результат
                result_data = {
                    'url': url,
                    'status': result['status'],
                    'content_length': len(result['content']),
                    'new_urls_count': len(new_urls),
                    'timestamp': time.time()
                }
                self.redis_client.hset(self.results_key, url, json.dumps(result_data))
            
            # Задержка между запросами
            await asyncio.sleep(config.get('delay', 0.1))
    
    async def worker_loop(self):
        """Основной цикл воркера"""
        print("Worker started. Waiting for tasks...")
        
        while True:
            try:
                # Получаем URL из очереди
                url = self.redis_client.rpop(self.queue_key)
                if not url:
                    await asyncio.sleep(1)
                    continue
                
                # Проверяем, не обработан ли уже URL
                if self.redis_client.sismember(self.processed_key, url):
                    continue
                
                # Помечаем URL как обрабатываемый
                self.redis_client.sadd(self.processed_key, url)
                
                print(f"Processing: {url}")
                
                try:
                    await self.process_url(url)
                except Exception as e:
                    print(f"Error processing {url}: {e}")
                    # Сохраняем ошибку
                    error_data = {
                        'url': url,
                        'error': str(e),
                        'status': 'error',
                        'timestamp': time.time()
                    }
                    self.redis_client.hset(self.results_key, url, json.dumps(error_data))
                    
            except redis.ConnectionError:
                print("Redis connection error. Retrying in 5 seconds...")
                await asyncio.sleep(5)
            except Exception as e:
                print(f"Unexpected error: {e}")
                await asyncio.sleep(1)

def main():
    """Запуск воркера"""
    crawler = DistributedCrawler()
    
    # Бесконечный цикл с переподключением при ошибках
    while True:
        try:
            asyncio.run(crawler.worker_loop())
        except KeyboardInterrupt:
            print("Worker stopped by user")
            break
        except Exception as e:
            print(f"Worker crashed: {e}. Restarting in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    main()