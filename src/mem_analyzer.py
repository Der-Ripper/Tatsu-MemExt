#!/usr/bin/env python3
"""
Простой анализатор дампов памяти Linux
"""

import argparse
import re
from collections import Counter
import os

class MemoryAnalyzer:
    def __init__(self, dump_file):
        self.dump_file = dump_file
        self.file_size = os.path.getsize(dump_file)
        
    def analyze_basic_info(self):
        """Базовая информация о дампе"""
        print("=" * 60)
        print("АНАЛИЗ ДАМПА ПАМЯТИ")
        print("=" * 60)
        print(f"Файл: {self.dump_file}")
        print(f"Размер: {self.file_size} байт ({self.file_size / 1024**3:.2f} GB)")
        print(f"Количество страниц: {self.file_size // 4096}")
        print("=" * 60)
        
    def extract_strings(self, min_length=4):
        """Извлечение читаемых строк из дампа"""
        print("Извлечение строк...")
        strings = []

        with open(self.dump_file, 'rb') as f:
            current_string = bytearray()
            file_size = os.path.getsize(self.dump_file)
            bytes_read = 0

            print(f"Размер файла: {file_size} байт")
            print("Прогресс: 0%", end='', flush=True)

            while True:
                chunk = f.read(4096)  # Читаем по страницам
                if not chunk:
                    break

                for byte in chunk:
                    if 32 <= byte <= 126:  # Печатные ASCII символы
                        current_string.append(byte)
                    else:
                        if len(current_string) >= min_length:
                            try:
                                strings.append(current_string.decode('utf-8'))
                            except UnicodeDecodeError:
                                pass
                        current_string = bytearray()

                bytes_read += len(chunk)
                percent = (bytes_read / file_size) * 100

                # Простой прогресс-бар
                if bytes_read % (10 * 1024 * 1024) == 0:  # Каждые 10MB
                    print(f"\rПрогресс: {percent:.1f}%", end='', flush=True)

            print(f"\rПрогресс: 100%   ")  # Завершаем прогресс-бар

        print(f"Извлечено строк: {len(strings)}")
        return strings
    
    def find_processes(self, strings):
        """Поиск информации о процессах"""
        print("\nПОИСК ПРОЦЕССОВ:")
        print("-" * 40)
        
        process_patterns = {
            'bash': r'bash|\.bash',
            'ssh': r'ssh(d)?|sshd',
            'python': r'python\d?',
            'java': r'java',
            'web': r'apache|nginx|httpd',
            'db': r'mysql|postgres|mongo',
            'system': r'systemd|init|kthread'
        }
        
        found_processes = []
        
        for pattern_name, pattern in process_patterns.items():
            matches = [s for s in strings if re.search(pattern, s, re.IGNORECASE)]
            if matches:
                print(f"{pattern_name.upper()}: найдено {len(matches)} упоминаний")
                for match in matches[:3]:  # Покажем первые 3 примера
                    print(f"  → {match[:100]}{'...' if len(match) > 100 else ''}")
                found_processes.extend(matches)
        
        return found_processes
    
    def find_system_info(self, strings):
        """Поиск системной информации"""
        print("\nСИСТЕМНАЯ ИНФОРМАЦИЯ:")
        print("-" * 40)
        
        # Поиск версии ядра
        kernel_versions = [s for s in strings if 'Linux version' in s]
        if kernel_versions:
            print("Версия ядра Linux:")
            for version in kernel_versions[:2]:
                print(f"  → {version}")
        
        # Поиск информации о CPU
        cpu_info = [s for s in strings if 'CPU' in s or 'processor' in s]
        if cpu_info:
            print("\nИнформация о CPU:")
            for info in cpu_info[:3]:
                print(f"  → {info}")
    
    def find_network_info(self, strings):
        """Поиск сетевой информации"""
        print("\nСЕТЕВАЯ ИНФОРМАЦИЯ:")
        print("-" * 40)
        
        # IP адреса
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_addresses = []
        for s in strings:
            ip_addresses.extend(re.findall(ip_pattern, s))
        
        if ip_addresses:
            print("IP адреса:")
            for ip in set(ip_addresses)[:10]:  # Уникальные адреса
                print(f"  → {ip}")
        
        # URL адреса
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = []
        for s in strings:
            urls.extend(re.findall(url_pattern, s))
        
        if urls:
            print("\nURL адреса:")
            for url in urls[:5]:
                print(f"  → {url}")
    
    def find_interesting_artifacts(self, strings):
        """Поиск интересных артефактов"""
        print("\nИНТЕРЕСНЫЕ АРТЕФАКТЫ:")
        print("-" * 40)
        
        # Команды
        commands = [s for s in strings if any(cmd in s for cmd in 
                     ['sudo', 'apt', 'curl', 'wget', 'git', 'docker'])]
        if commands:
            print("Команды:")
            for cmd in commands[:5]:
                print(f"  → {cmd}")
        
        # Файловые пути
        paths = [s for s in strings if s.startswith(('/home/', '/etc/', '/var/'))]
        if paths:
            print("\nФайловые пути:")
            for path in paths[:5]:
                print(f"  → {path}")
    
    def analyze(self):
        """Основной метод анализа"""
        self.analyze_basic_info()
        
        # Извлекаем строки
        strings = self.extract_strings()
        print(f"Извлечено строк: {len(strings)}")
        
        # Анализируем данные
        self.find_processes(strings)
        self.find_system_info(strings)
        self.find_network_info(strings)
        self.find_interesting_artifacts(strings)
        
        print("\n" + "=" * 60)
        print("АНАЛИЗ ЗАВЕРШЕН!")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='Анализатор дампов памяти Linux')
    parser.add_argument('dump_file', help='Путь к файлу дампа')
    parser.add_argument('--output', '-o', help='Файл для сохранения результатов')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dump_file):
        print(f"Ошибка: Файл {args.dump_file} не найден!")
        return
    
    analyzer = MemoryAnalyzer(args.dump_file)
    analyzer.analyze()
    
    if args.output:
        # Сохранение результатов в файл
        import sys
        original_stdout = sys.stdout
        with open(args.output, 'w', encoding='utf-8') as f:
            sys.stdout = f
            analyzer.analyze()
            sys.stdout = original_stdout
        print(f"\nРезультаты сохранены в: {args.output}")

if __name__ == "__main__":
    main()