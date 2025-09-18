import struct
import re
import json
from pathlib import Path
from datetime import datetime

class LinuxMemoryAnalyzer:
    def __init__(self, dump_path):
        self.dump_path = Path(dump_path)
        self.analysis_results = {}
        self.dump_size = self.dump_path.stat().st_size if self.dump_path.exists() else 0
        self.buffer_size = 1024 * 1024  # 1MB буфер для чтения
    
    def print_progress(self, message, step=None, total_steps=None):
        """Вывод прогресса в терминал"""
        if step and total_steps:
            print(f"[{step}/{total_steps}] {message}")
        else:
            print(f"[INFO] {message}")
    
    def read_string_at_offset(self, offset, max_length=256):
        """Чтение строки из определенного смещения"""
        try:
            with open(self.dump_path, 'rb') as f:
                f.seek(offset)
                data = f.read(max_length)
                end = data.find(b'\x00')
                if end != -1:
                    data = data[:end]
                return data.decode('utf-8', errors='ignore')
        except:
            return ""
    
    def search_pattern(self, pattern, max_matches=100):
        """Поиск паттерна в дампе"""
        matches = []
        pattern_bytes = pattern.encode('utf-8')
        pattern_len = len(pattern_bytes)
        
        try:
            with open(self.dump_path, 'rb') as f:
                chunk_size = self.buffer_size
                offset = 0
                
                while offset < self.dump_size:
                    f.seek(offset)
                    data = f.read(chunk_size)
                    
                    if not data:
                        break
                    
                    pos = 0
                    while pos < len(data) - pattern_len:
                        found_pos = data.find(pattern_bytes, pos)
                        if found_pos == -1:
                            break
                        
                        absolute_pos = offset + found_pos
                        
                        # Читаем контекст вокруг найденного паттерна
                        context_start = max(0, found_pos - 50)
                        context_end = min(len(data), found_pos + pattern_len + 50)
                        context = data[context_start:context_end]
                        
                        try:
                            context_str = context.decode('utf-8', errors='ignore')
                        except:
                            context_str = context.hex()
                        
                        matches.append({
                            'offset': absolute_pos,
                            'hex_offset': hex(absolute_pos),
                            'context': context_str,
                            'pattern': pattern
                        })
                        
                        if len(matches) >= max_matches:
                            break
                        
                        pos = found_pos + pattern_len
                    
                    if len(matches) >= max_matches:
                        break
                    
                    offset += chunk_size - pattern_len
                    
        except Exception as e:
            self.print_progress(f"Error searching pattern '{pattern}': {e}")
        
        return matches
    
    def analyze_basic_info(self):
        """Базовый анализ дампа"""
        self.print_progress("Starting basic info analysis", 1, 6)
        
        try:
            self.analysis_results['basic_info'] = {
                'dump_size': self.dump_size,
                'dump_size_human': f"{self.dump_size / (1024*1024*1024):.2f} GB",
                'analysis_date': datetime.now().isoformat(),
                'file_path': str(self.dump_path),
                'file_exists': self.dump_path.exists(),
                'analysis_duration': 'in progress'
            }
            return True
        except Exception as e:
            self.analysis_results['basic_info_error'] = str(e)
            return False
    
    def analyze_kernel_info(self):
        """Анализ информации о ядре"""
        self.print_progress("Analyzing kernel information", 2, 6)
        
        kernel_info = {}
        try:
            # Поиск информации о версии ядра
            kernel_patterns = [
                'Linux version',
                'kernel version',
                'Release:',
                'PRETTY_NAME=',
                'NAME=',
                'VERSION='
            ]
            
            for pattern in kernel_patterns:
                matches = self.search_pattern(pattern, max_matches=5)
                if matches:
                    kernel_info[pattern] = matches
            
            self.analysis_results['kernel_info'] = kernel_info
            return kernel_info
            
        except Exception as e:
            error_msg = f"Kernel info error: {str(e)}"
            self.analysis_results['kernel_info_error'] = error_msg
            return {'error': error_msg}
    
    def analyze_processes(self):
        """Анализ процессов"""
        self.print_progress("Analyzing processes", 3, 6)
        
        processes_info = {}
        try:
            # Поиск информации о процессах
            process_patterns = [
                'bash',
                'ssh',
                'python',
                'java',
                'systemd',
                'init',
                'kthread',
                'docker',
                'kube',
                'nginx',
                'apache',
                'mysql'
            ]
            
            for pattern in process_patterns:
                matches = self.search_pattern(pattern, max_matches=10)
                if matches:
                    processes_info[pattern] = {
                        'count': len(matches),
                        'matches': matches[:5]  # Ограничиваем вывод
                    }
            
            self.analysis_results['processes'] = processes_info
            return processes_info
            
        except Exception as e:
            error_msg = f"Process analysis error: {str(e)}"
            self.analysis_results['processes_error'] = error_msg
            return {'error': error_msg}
    
    def analyze_network_info(self):
        """Анализ сетевой информации"""
        self.print_progress("Analyzing network information", 4, 6)
        
        network_info = {}
        try:
            # Поиск IP адресов
            ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b'
            
            # Читаем первые 100MB для поиска IP
            with open(self.dump_path, 'rb') as f:
                data = f.read(min(self.dump_size, 100 * 1024 * 1024))
                text_data = data.decode('utf-8', errors='ignore')
            
            # Ищем IPv4
            ipv4_matches = re.findall(ipv4_pattern, text_data)
            unique_ipv4 = sorted(set(ip for ip in ipv4_matches if not ip.startswith('0.') and ip != '0.0.0.0'))
            
            # Ищем сетевые паттерны
            network_patterns = [
                'tcp', 'udp', 'port', 'socket', 'connect',
                'http', 'https', 'ftp', 'ssh', 'dns'
            ]
            
            network_data = {}
            for pattern in network_patterns:
                matches = self.search_pattern(pattern, max_matches=5)
                if matches:
                    network_data[pattern] = matches
            
            network_info = {
                'ipv4_addresses': unique_ipv4[:50],  # Ограничиваем количество
                'network_activities': network_data
            }
            
            self.analysis_results['network'] = network_info
            return network_info
            
        except Exception as e:
            error_msg = f"Network analysis error: {str(e)}"
            self.analysis_results['network_error'] = error_msg
            return {'error': error_msg}
    
    def analyze_user_info(self):
        """Анализ пользовательской информации"""
        self.print_progress("Analyzing user information", 5, 6)
        
        user_info = {}
        try:
            # Поиск пользовательской информации
            user_patterns = [
                'root', 'admin', 'user', 'login', 'password',
                'passwd', 'shadow', 'sudo', 'su ', 'ssh-key',
                '/home/', '/root/', '/etc/passwd', '/etc/shadow'
            ]
            
            for pattern in user_patterns:
                matches = self.search_pattern(pattern, max_matches=5)
                if matches:
                    user_info[pattern] = matches
            
            self.analysis_results['users'] = user_info
            return user_info
            
        except Exception as e:
            error_msg = f"User analysis error: {str(e)}"
            self.analysis_results['users_error'] = error_msg
            return {'error': error_msg}
    
    def analyze_system_configs(self):
        """Анализ системных конфигураций"""
        self.print_progress("Analyzing system configurations", 6, 6)
        
        config_info = {}
        try:
            # Поиск конфигурационных файлов и настроек
            config_patterns = [
                'config', 'conf', 'ini', 'cfg', 'yml', 'yaml',
                'json', 'xml', 'properties', 'env', 'export',
                'PATH=', 'HOME=', 'SHELL=', 'USER='
            ]
            
            for pattern in config_patterns:
                matches = self.search_pattern(pattern, max_matches=3)
                if matches:
                    config_info[pattern] = matches
            
            self.analysis_results['configs'] = config_info
            return config_info
            
        except Exception as e:
            error_msg = f"Config analysis error: {str(e)}"
            self.analysis_results['configs_error'] = error_msg
            return {'error': error_msg}
    
    def full_analysis(self):
        """Полный анализ дампа"""
        start_time = datetime.now()
        self.print_progress(f"Starting full analysis of {self.dump_path}")
        self.print_progress(f"Dump size: {self.dump_size} bytes ({self.dump_size/1024/1024/1024:.2f} GB)")
        
        try:
            if not self.dump_path.exists():
                raise FileNotFoundError(f"Dump file not found: {self.dump_path}")
            
            if self.dump_size == 0:
                raise ValueError("Dump file is empty")
            
            # Выполняем все этапы анализа
            self.analyze_basic_info()
            self.analyze_kernel_info()
            self.analyze_processes()
            self.analyze_network_info()
            self.analyze_user_info()
            self.analyze_system_configs()
            
            # Добавляем информацию о времени выполнения
            analysis_duration = (datetime.now() - start_time).total_seconds()
            self.analysis_results['analysis_summary'] = {
                'total_sections': len(self.analysis_results),
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': analysis_duration,
                'status': 'completed',
                'dump_valid': True
            }
            
            self.print_progress(f"Analysis completed in {analysis_duration:.2f} seconds")
            self.print_progress(f"Found {len(self.analysis_results)} analysis sections")
            
            return self.analysis_results
            
        except Exception as e:
            error_msg = f"Full analysis failed: {str(e)}"
            self.print_progress(f"ERROR: {error_msg}")
            
            return {
                'error': error_msg,
                'dump_path': str(self.dump_path),
                'dump_exists': self.dump_path.exists(),
                'dump_size': self.dump_size,
                'analysis_time': datetime.now().isoformat(),
                'status': 'failed'
            }