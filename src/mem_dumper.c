/*
 * Memory Dumper Kernel Module
 * Creates a physical RAM dump for Volatility analysis
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>        // struct page, pfn_to_page, kmap, kunmap
#include <linux/fs.h>        // filp_open, filp_close, vfs_write
#include <linux/string.h>    // memcpy
#include <linux/uaccess.h>   // set_fs, get_fs, KERNEL_DS
#include <linux/memory_hotplug.h> // max_pfn

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DFIR Analyst");
MODULE_DESCRIPTION("Physical Memory Dumper Module");

/* --- Параметры модуля --- */
static char *dump_path = "/tmp/memory.dmp"; // Путь по умолчанию
module_param(dump_path, charp, 0000);
MODULE_PARM_DESC(dump_path, "Path to save the memory dump");

/* --- Глобальные переменные --- */
static struct file *output_file;
static loff_t file_position;

/* --- Функция для безопасной записи в файл из пространства ядра --- */
static int file_write(const char *buffer, size_t length) {
    mm_segment_t old_fs;
    int bytes_written;

    // Временно подменяем сегмент доступа на ядерный
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    // Выполняем запись
    bytes_written = vfs_write(output_file, buffer, length, &file_position);

    // Восстанавливаем оригинальный сегмент доступа
    set_fs(old_fs);

    return bytes_written;
}

/* --- Функция дампа одной страницы памяти --- */
static int dump_page(unsigned long pfn) {
    struct page *page_ptr;
    void *mapped_address;
    char *page_buffer;
    int result = 0;

    // 1. Получаем указатель на структуру страницы
    page_ptr = pfn_to_page(pfn);
    if (!page_ptr) {
        return -1; // Несуществующий PFN
    }

    // 2. Проецируем физическую страницу в виртуальное адресное пространство ядра
    mapped_address = kmap(page_ptr);
    if (!mapped_address) {
        return -1; // Ошибка отображения
    }

    // 3. Выделяем буфер для копирования данных страницы
    page_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!page_buffer) {
        kunmap(page_ptr);
        return -1;
    }

    // 4. Копируем данные из отображенной памяти в наш буфер
    memcpy(page_buffer, mapped_address, PAGE_SIZE);

    // 5. Пишем содержимое буфера в файл
    if (file_write(page_buffer, PAGE_SIZE) != PAGE_SIZE) {
        result = -1; // Ошибка записи
    }

    // 6. Обязательно освобождаем ресурсы!
    kfree(page_buffer);
    kunmap(page_ptr);

    return result;
}

/* --- Основная функция создания дампа --- */
static void create_memory_dump(void) {
    unsigned long pfn;
    unsigned long max_pfn_value;
    int error_count = 0;

    printk(KERN_INFO "MemDumper: Starting memory dump to %s\n", dump_path);

    // Получаем максимальный номер страницы (PFN) в системе
    max_pfn_value = get_max_pfn();

    printk(KERN_INFO "MemDumper: Max PFN is %lu, total pages ~%lu\n", 
           max_pfn_value, max_pfn_value);

    // Открываем файл для записи (создаем или перезаписываем)
    output_file = filp_open(dump_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (IS_ERR(output_file)) {
        printk(KERN_ERR "MemDumper: FATAL: Cannot open output file!\n");
        return;
    }

    file_position = 0; // Начинаем запись с начала файла

    // Главный цикл: итерируемся по всем существующим страницам памяти
    for (pfn = 0; pfn < max_pfn_value; pfn++) {
        if (dump_page(pfn) != 0) {
            error_count++;
            // Не выводим лог для каждой ошибки, чтобы не засорять кольцевой буфер
        }
    }

    // Все страницы обработаны, закрываем файл
    filp_close(output_file, NULL);

    printk(KERN_INFO "MemDumper: Dump complete. Pages processed: %lu, errors: %d\n", 
           max_pfn_value, error_count);
    printk(KERN_INFO "MemDumper: Output file: %s\n", dump_path);
}

/* --- Инициализация модуля --- */
static int __init mem_dumper_init(void) {
    printk(KERN_INFO "MemDumper: Module loaded. Beginning dump process...\n");
    
    // Вызываем функцию дампа сразу при загрузке модуля
    create_memory_dump();
    
    // После завершения дампа модуль можно выгружать
    return 0;
}

/* --- Выгрузка модуля --- */
static void __exit mem_dumper_exit(void) {
    printk(KERN_INFO "MemDumper: Module unloaded.\n");
}

// Регистрируем функции инициализации и очистки
module_init(mem_dumper_init);
module_exit(mem_dumper_exit);