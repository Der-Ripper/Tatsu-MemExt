import os
import re
import time
import struct
from collections import defaultdict

def analyze_dump(dump_path):
    """
    Улучшенный анализатор дампа памяти - ищет реальные структуры данных
    """
    print(f"Starting enhanced analysis of: {dump_path}")
    result = {
        'os_info': {},
        'processes': [],
        'network_connections': [],
        'strings_found': [],
        'status': 'completed',
        'analysis_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'file_size_gb': os.path.getsize(dump_path) / (1024**3)
    }
    
    try:
        file_size = os.path.getsize(dump_path)
        print(f"File size: {file_size/(1024*1024*1024):.2f} GB")
        
        # Анализируем разные области файла
        with open(dump_path, 'rb') as f:
            # 1. Анализ ядра Linux (первые 2MB)
            print("Analyzing kernel structures...")
            kernel_data = f.read(2 * 1024 * 1024)  # 2MB
            result['os_info'] = extract_linux_info(kernel_data)
            
            # 2. Поиск строк throughout файла
            print("Searching for readable strings...")
            f.seek(0)
            result['strings_found'] = find_meaningful_strings(f, file_size)
            
            # 3. Поиск сетевой информации
            print("Searching for network information...")
            f.seek(0)
            result['network_connections'] = find_network_info(f, file_size)
            
            # 4. Поиск информации о процессах
            print("Searching for process information...")
            f.seek(0)
            result['processes'] = find_process_info(f, file_size)
            
        print(f"Enhanced analysis completed")
        
    except Exception as e:
        print(f"Error analyzing dump: {e}")
        import traceback
        traceback.print_exc()
        result['error'] = str(e)
        result['status'] = 'error'
    
    return result

def extract_linux_info(data):
    """Извлекает информацию о Linux системе"""
    info = {}
    
    # Поиск версии ядра Linux (более надежные паттерны)
    kernel_patterns = [
        rb'Linux version (\d+\.\d+\.\d+[-\w+]*)',
        rb'#(\d+)-[A-Za-z]+\s+SMP',
        rb'SMP.*?(\d+\.\d+\.\d+[-\w+]*)',
        rb'PREEMPT.*?(\d+\.\d+\.\d+[-\w+]*)'
    ]
    
    for pattern in kernel_patterns:
        match = re.search(pattern, data, re.IGNORECASE)
        if match:
            try:
                info['kernel_version'] = match.group(1).decode('utf-8', errors='ignore')
                print(f"   Found kernel: {info['kernel_version']}")
                break
            except:
                continue
    
    # Поиск архитектуры
    arch_patterns = {
        'x86_64': [rb'x86_64', rb'AMD64', rb'lmae'],
        'i386': [rb'i386', rb'i686', rb'x86'],
        'arm': [rb'ARM', rb'armv', rb'aarch'],
        'aarch64': [rb'aarch64', rb'arm64']
    }
    
    for arch, patterns in arch_patterns.items():
        for pattern in patterns:
            if re.search(pattern, data, re.IGNORECASE):
                info['architecture'] = arch
                print(f"   Found architecture: {arch}")
                break
        if 'architecture' in info:
            break
    
    # Поиск информации о дистрибутиве
    distro_patterns = [
        (rb'Ubuntu', 'Ubuntu'),
        (rb'Debian', 'Debian'),
        (rb'CentOS', 'CentOS'),
        (rb'Red Hat', 'Red Hat'),
        (rb'Fedora', 'Fedora'),
        (rb'SUSE', 'SUSE'),
        (rb'Gentoo', 'Gentoo'),
        (rb'Arch Linux', 'Arch')
    ]
    
    for pattern, distro in distro_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            info['distribution'] = distro
            print(f"   Found distribution: {distro}")
            break
    
    return info

def find_meaningful_strings(f, file_size):
    """Поиск осмысленных строк в дампе"""
    strings = []
    string_pattern = rb'[\\x20-\\x7E]{8,500}'  # Более длинные строки
    
    # Проверяем стратегические позиции в файле
    sample_positions = [
        0,                          # Начало (ядро)
        file_size // 8,             # 12.5%
        file_size // 4,             # 25%
        file_size // 2,             # 50%
        file_size * 3 // 4,         # 75%
        file_size - (2 * 1024 * 1024)  # Конец (стек/куча)
    ]
    
    meaningful_keywords = [
        'linux', 'ubuntu', 'debian', 'centos', 'redhat', 'fedora',
        'http://', 'https://', 'tcp', 'udp', 'ssh', 'bash', 'python',
        'mysql', 'apache', 'nginx', 'docker', 'kube', 'systemd',
        'root', 'home', 'etc/', 'var/', 'proc/', 'sys/', 'dev/'
    ]
    
    for pos in sample_positions:
        if pos < file_size:
            f.seek(pos)
            data = f.read(65536)  # 64KB чанки
            
            matches = re.finditer(string_pattern, data)
            for match in matches:
                try:
                    string = match.group(0).decode('utf-8', errors='ignore')
                    # Проверяем на осмысленность
                    if (len(string) >= 10 and 
                        any(keyword in string.lower() for keyword in meaningful_keywords) and
                        not string.isdigit()):
                        
                        strings.append({
                            'string': string[:200],  # Обрезаем длинные строки
                            'offset': pos + match.start(),
                            'context': 'memory_dump'
                        })
                        
                except:
                    continue
    
    # Убираем дубликаты и ограничиваем количество
    unique_strings = []
    seen_strings = set()
    
    for s in strings:
        if s['string'] not in seen_strings:
            unique_strings.append(s)
            seen_strings.add(s['string'])
    
    return unique_strings[:50]

def find_network_info(f, file_size):
    """Поиск сетевой информации"""
    connections = []
    
    # Паттерны для сетевой информации
    ip_pattern = rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    mac_pattern = rb'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b'
    url_pattern = rb'https?://[^\s<>"{}|\\^`\[\]]+'
    
    # Проверяем разные области файла
    sample_positions = [
        0,
        file_size // 4,
        file_size // 2,
        file_size * 3 // 4
    ]
    
    for pos in sample_positions:
        if pos < file_size:
            f.seek(pos)
            data = f.read(131072)  # 128KB
            
            # IP адреса
            ip_matches = re.finditer(ip_pattern, data)
            for match in ip_matches:
                try:
                    ip = match.group(0).decode('utf-8')
                    if all(0 <= int(part) <= 255 for part in ip.split('.')):
                        connections.append({
                            'type': 'ip_address',
                            'value': ip,
                            'offset': pos + match.start()
                        })
                except:
                    continue
            
            # MAC адреса
            mac_matches = re.finditer(mac_pattern, data, re.IGNORECASE)
            for match in mac_matches:
                try:
                    mac = match.group(0).decode('utf-8')
                    connections.append({
                        'type': 'mac_address',
                        'value': mac,
                        'offset': pos + match.start()
                    })
                except:
                    continue
    
    # Убираем дубликаты
    unique_connections = []
    seen_values = set()
    
    for conn in connections:
        if conn['value'] not in seen_values:
            unique_connections.append(conn)
            seen_values.add(conn['value'])
    
    return unique_connections[:30]

def find_process_info(f, file_size):
    """Поиск информации о процессах"""
    processes = []
    
    # Паттерны для процессов и путей
    process_patterns = [
        rb'/proc/\d+',
        rb'/bin/[a-zA-Z0-9_\-]+',
        rb'/usr/bin/[a-zA-Z0-9_\-]+',
        rb'/sbin/[a-zA-Z0-9_\-]+',
        rb'/usr/sbin/[a-zA-Z0-9_\-]+',
        rb'[a-zA-Z0-9_\-]+\.sh\b',
        rb'python\d?\.?\d?',
        rb'bash|zsh|sh|dash',
        rb'sshd|nginx|apache|mysql|postgres',
        rb'docker|kube|containerd'
    ]
    
    # Ключевые слова для процессов
    process_keywords = [
        'pid', 'ppid', 'comm', 'task_struct', 'process',
        'thread', 'exec', 'fork', 'clone'
    ]
    
    sample_positions = [
        file_size // 8,
        file_size // 4,
        file_size // 2,
        file_size * 3 // 4
    ]
    
    for pos in sample_positions:
        if pos < file_size:
            f.seek(pos)
            data = f.read(65536)
            
            for pattern in process_patterns:
                matches = re.finditer(pattern, data, re.IGNORECASE)
                for match in matches:
                    try:
                        process_str = match.group(0).decode('utf-8', errors='ignore')
                        if (len(process_str) >= 4 and 
                            not process_str.isdigit() and
                            any(keyword in process_str.lower() for keyword in process_keywords)):
                            
                            processes.append({
                                'name': process_str[:100],
                                'type': 'process_reference',
                                'offset': pos + match.start()
                            })
                    except:
                        continue
    
    # Убираем дубликаты
    unique_processes = []
    seen_names = set()
    
    for proc in processes:
        if proc['name'] not in seen_names:
            unique_processes.append(proc)
            seen_names.add(proc['name'])
    
    return unique_processes[:20]

# Дополнительная функция для детального анализа
def detailed_analysis(dump_path):
    """Более детальный анализ для больших дампов"""
    print(f"Starting detailed analysis of: {dump_path}")
    
    results = {
        'sections': [],
        'potential_artifacts': []
    }
    
    # Здесь можно добавить более сложный анализ
    
    return results