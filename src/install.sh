#!/bin/bash

# Скрипт для автоматизации установки и использования модуля mem_dumper
# Требует прав root для выполнения

set -e  # Завершать скрипт при любой ошибке

# Глобальные переменные
PROJECT_DIR="mem_dumper"
MODULE_NAME="mem_dumper"
DUMP_PATH="tcp:192.168.56.1:4444"  # Глобальная переменная скрипта

# Функция для проверки прав root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Ошибка: Скрипт должен запускаться с правами root"
        exit 1
    fi
}

# Функция для установки заголовков ядра
install_kernel_headers() {
    echo "Установка заголовков ядра..."
    
    # Проверяем, установлены ли уже заголовки
    if dpkg -l | grep -q "linux-headers-$(uname -r)"; then
        echo "Заголовки ядра уже установлены"
        return 0
    fi
    
    # Устанавливаем только необходимые пакеты без обновления
    apt install -y --no-upgrade build-essential linux-headers-$(uname -r)
    
    echo "Заголовки ядра установлены успешно"
}

# Функция для создания директории проекта
create_project_dir() {
    echo "Создание директории проекта..."
    if [ -d "$PROJECT_DIR" ]; then
        echo "Директория $PROJECT_DIR уже существует, удаляем..."
        rm -rf "$PROJECT_DIR"
    fi
    mkdir -p "$PROJECT_DIR"
    cd "$PROJECT_DIR"
    echo "Перешли в директорию: $(pwd)"
}

# Функция для скачивания файлов
download_files() {
    echo "Скачивание файлов..."
    
    # URL файлов (raw версии)
    MEM_DUMPER_URL="https://raw.githubusercontent.com/Der-Ripper/Tatsu-MemExt/main/src/mem_dumper.c"
    MAKEFILE_URL="https://raw.githubusercontent.com/Der-Ripper/Tatsu-MemExt/main/src/Makefile"
    
    # Скачиваем файлы
    if command -v wget &> /dev/null; then
        wget -q "$MEM_DUMPER_URL"
        wget -q "$MAKEFILE_URL"
    elif command -v curl &> /dev/null; then
        curl -s -O "$MEM_DUMPER_URL"
        curl -s -O "$MAKEFILE_URL"
    else
        echo "Ошибка: Не найдены wget или curl для скачивания файлов"
        exit 1
    fi
    
    # Проверяем, что файлы скачались
    if [ ! -f "mem_dumper.c" ] || [ ! -f "Makefile" ]; then
        echo "Ошибка: Не удалось скачать файлы"
        exit 1
    fi
    
    echo "Файлы успешно скачаны"
}

# Функция для сборки модуля
build_module() {
    echo "Сборка модуля..."
    make
    if [ ! -f "${MODULE_NAME}.ko" ]; then
        echo "Ошибка: Не удалось собрать модуль"
        exit 1
    fi
    echo "Модуль успешно собран"
}

# Функция для загрузки модуля
load_module() {
    echo "Загрузка модуля с параметром dump_path=$DUMP_PATH"
    if insmod "${MODULE_NAME}.ko" dump_path="$DUMP_PATH"; then
        echo "Модуль успешно загружен"
        # Показываем информацию о загруженном модуле
        sleep 2
        lsmod | grep "$MODULE_NAME" || true
    else
        echo "Ошибка при загрузке модуля"
        exit 1
    fi
}

# Функция для выгрузки модуля
unload_module() {
    echo "Выгрузка модуля..."
    if rmmod "$MODULE_NAME"; then
        echo "Модуль успешно выгружен"
    else
        echo "Ошибка при выгрузке модуля"
        exit 1
    fi
}

# Функция для очистки
cleanup() {
    echo "Очистка..."
    make clean
    cd ..
    rm -rf "$PROJECT_DIR"
    echo "Директория $PROJECT_DIR удалена"
}

# Основная функция
main() {
    echo "=== Начало автоматизации модуля mem_dumper ==="
    echo "Используется dump_path: $DUMP_PATH"
    
    check_root
    install_kernel_headers
    create_project_dir
    download_files
    build_module
    load_module
    
    echo "Модуль работает... Нажмите Ctrl+C для завершения или подождите"
    sleep 5  # Даем время модулю поработать
    
    unload_module
    cleanup
    
    echo "=== Процесс завершен успешно ==="
}

# Обработка сигналов для graceful shutdown
trap 'echo "Прерывание..."; unload_module; cleanup; exit 0' INT TERM

# Запуск основной функции
main "$@"