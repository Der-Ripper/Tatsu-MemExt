/*
 * Memory Dumper Kernel Module
 * Creates a physical RAM dump for Volatility analysis
 * Compatible with Linux kernels
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>        // struct page, pfn_to_page, pfn_valid
#include <linux/fs.h>        // filp_open, filp_close
#include <linux/string.h>    // memcpy
#include <linux/slab.h>      // kmalloc, kfree
#include <linux/version.h>   // LINUX_VERSION_CODE, KERNEL_VERSION
#include <linux/uaccess.h>   // Для ядер: get_fs, set_fs
#include <linux/highmem.h>   // Для kmap_atomic, kunmap_atomic

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DFIR Analyst");
MODULE_DESCRIPTION("Universal Physical Memory Dumper Module");

/* --- Параметры модуля --- */
static char *dump_path = "/home/tatsu-victim/memory.dmp"; // Путь по умолчанию
module_param(dump_path, charp, 0000);
MODULE_PARM_DESC(dump_path, "Path to save the memory dump");

/* --- Глобальные переменные --- */
static struct file *output_file;
static loff_t file_position;

/* --- Функция для безопасной записи в файл из пространства ядра --- */
static int file_write(const char *buffer, size_t length) {
    ssize_t bytes_written;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    /* --- Реализация для старых ядер (<5.10) --- */
    mm_segment_t old_fs;
    
    // Временно подменяем сегмент доступа на ядерный
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    
    // Выполняем запись
    bytes_written = vfs_write(output_file, buffer, length, &file_position);
    
    // Восстанавливаем оригинальный сегмент доступа
    set_fs(old_fs);
#else
    /* --- Реализация для новых ядер (>=5.10) --- */
    bytes_written = kernel_write(output_file, buffer, length, &file_position);
#endif

    if (bytes_written < 0) {
        printk(KERN_ERR "MemDumper: Write error: %ld\n", bytes_written);
        return -1;
    }
    
    // Обновляем позицию в файле для следующей записи
    file_position += bytes_written;
    
    return bytes_written;
}

/* --- Функция дампа одной страницы памяти --- */
static int dump_memory_page(unsigned long pfn) {
    struct page *page_ptr;
    void *mapped_address;
    char *page_buffer;
    int result = 0;

    // 1. Проверяем валидность PFN
    if (!pfn_valid(pfn)) {
        return -1;
    }
    
    // 2. Получаем указатель на структуру страницы
    page_ptr = pfn_to_page(pfn);
    if (!page_ptr) {
        return -1;
    }

    // 3. Проецируем физическую страницу в виртуальное адресное пространство ядра
    mapped_address = kmap_atomic(page_ptr);
    if (!mapped_address) {
        return -1;
    }

    // 4. Выделяем буфер для копирования данных страницы
    page_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!page_buffer) {
        kunmap_atomic(mapped_address);
        return -1;
    }

    // 5. Копируем данные из отображенной памяти в наш буфер
    memcpy(page_buffer, mapped_address, PAGE_SIZE);

    // 6. Пишем содержимое буфера в файл
    if (file_write(page_buffer, PAGE_SIZE) != PAGE_SIZE) {
        result = -1;
    }

    // 7. Обязательно освобождаем ресурсы!
    kfree(page_buffer);
    kunmap_atomic(mapped_address);

    return result;
}

/* --- Основная функция создания дампа --- */
static void create_memory_dump(void) {
    unsigned long pfn;
    unsigned long max_pfn_value;
    int error_count = 0;

    printk(KERN_INFO "MemDumper: Starting memory dump to %s\n", dump_path);

    // Получаем максимальный номер страницы (PFN) из системной информации
    // Вместо прямого доступа к max_pfn, используем системные лимиты
    max_pfn_value = (totalram_pages() + totalhigh_pages()) * 2; // Консервативная оценка

    printk(KERN_INFO "MemDumper: Estimated max PFN: %lu\n", max_pfn_value);

    // Открываем файл для записи (создаем или перезаписываем)
    output_file = filp_open(dump_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (IS_ERR(output_file)) {
        printk(KERN_ERR "MemDumper: FATAL: Cannot open output file! Error: %ld\n", PTR_ERR(output_file));
        return;
    }

    file_position = 0; // Начинаем запись с начала файла

    // Главный цикл: итерируемся по возможным страницам памяти
    // Будем пробовать до консервативного лимита
    for (pfn = 0; pfn < max_pfn_value; pfn++) {
        if (pfn % 10000 == 0 && pfn > 0) {
            printk(KERN_INFO "MemDumper: Processed %lu pages\n", pfn);
        }
        
        if (dump_memory_page(pfn) != 0) {
            error_count++;
            // Если подряд много ошибок, возможно, достигли конца памяти
            if (error_count > 1000 && pfn > 100000) {
                printk(KERN_INFO "MemDumper: Reached end of memory at PFN %lu\n", pfn);
                break;
            }
        }
    }

    // Все страницы обработаны, закрываем файл
    filp_close(output_file, NULL);

    printk(KERN_INFO "MemDumper: Dump complete. Pages processed: %lu, errors: %d\n", 
           pfn, error_count);
    printk(KERN_INFO "MemDumper: Output file: %s (Size: %lu bytes)\n", 
           dump_path, file_position);
}

/* --- Инициализация модуля --- */
static int __init mem_dumper_init(void) {
    printk(KERN_INFO "MemDumper: Module loaded. Beginning dump process...\n");
    
    // Вызываем функцию дампа сразу при загрузке модуля
    create_memory_dump();
    
    return 0;
}

/* --- Выгрузка модуля --- */
static void __exit mem_dumper_exit(void) {
    printk(KERN_INFO "MemDumper: Module unloaded.\n");
}

// Регистрируем функции инициализации и очистки
module_init(mem_dumper_init);
module_exit(mem_dumper_exit);