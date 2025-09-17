/*
 * Memory Dumper Kernel Module with optional TCP streaming
 * - Supports dump_path as either a filesystem path or "tcp:IP:PORT"
 * - Preserves version-specific file write logic (pre/post 5.10)
 *
 * Usage examples:
 *  - file: insmod mem_dumper.ko dump_path=/root/memory.dmp
 *  - tcp:  insmod mem_dumper.ko dump_path=tcp:192.168.56.1:31337
 *
 * On the collector (host) to receive a TCP stream:
 *   # nc -l -p 31337 > memory.dmp
 *
 * Build with your normal kernel build (Makefile provided earlier).
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/memblock.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DFIR Analyst");
MODULE_DESCRIPTION("Physical Memory Dumper Module with TCP streaming support");

static char *dump_path = "/home/tatsu-victim/memory.dmp";
module_param(dump_path, charp, 0000);
MODULE_PARM_DESC(dump_path, "Path to save the memory dump OR tcp:IP:PORT to stream");

static struct file *output_file;
static loff_t file_position;

/* TCP globals */
static struct socket *mem_sock = NULL;
static bool use_tcp = false;
static __be32 remote_addr_be = 0;
static unsigned short remote_port = 0;

/* MAX_RW_COUNT conservative fallback */
#ifndef MAX_RW_COUNT
#define MAX_RW_COUNT ((ssize_t)0x7ffff000)
#endif

// Макросы для проверки доступности API
#ifdef CONFIG_MMU
#define HAVE_OOM_ADJ 1
#else
#define HAVE_OOM_ADJ 0
#endif

/* ---------- Networking helpers ---------- */

/* parse dump_path like "tcp:192.168.56.1:31337"
 * returns 0 on success (and sets use_tcp, remote_addr_be, remote_port),
 * returns -EINVAL on parse error.
 */
static int parse_tcp_path(const char *path)
{
    const char *p = path + 4; /* skip "tcp:" */
    char ipbuf[64];
    char *colon;
    int iplen;
    unsigned long port_ul;

    if (!p || *p == '\0')
        return -EINVAL;

    colon = strrchr(p, ':');
    if (!colon)
        return -EINVAL;

    iplen = colon - p;
    if (iplen <= 0 || iplen >= (int)sizeof(ipbuf))
        return -EINVAL;

    memcpy(ipbuf, p, iplen);
    ipbuf[iplen] = '\0';

    /* parse port */
    if (kstrtoul(colon + 1, 10, &port_ul) != 0)
        return -EINVAL;
    if (port_ul == 0 || port_ul > 65535)
        return -EINVAL;

    /* convert IP string to network-order __be32 */
    remote_addr_be = in_aton(ipbuf); /* returns __be32 in host byte order? in_aton returns u32 in network order */
    /* in_aton returns value in network byte order (big-endian), that's fine for sin_addr.s_addr */

    remote_port = (unsigned short)port_ul;

    use_tcp = true;
    return 0;
}

/* create and connect kernel socket to remote (IPv4)
 * returns 0 on success, negative errno on failure
 */
static int connect_to_remote(void)
{
    struct sockaddr_in saddr;
    int ret;

    if (!use_tcp)
        return -EINVAL;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &mem_sock);
    if (ret < 0 || !mem_sock) {
        pr_err("MemDumper: sock_create_kern failed: %d\n", ret);
        mem_sock = NULL;
        return ret ? ret : -ENOMEM;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = remote_addr_be; /* already in network order */
    saddr.sin_port = htons(remote_port);

    /* kernel_connect available on modern kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
    ret = kernel_connect(mem_sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
#else
    /* older kernels might require different connect path; attempt generic call */
    ret = mem_sock->ops->connect(mem_sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
#endif

    if (ret < 0) {
        pr_err("MemDumper: kernel_connect failed: %d\n", ret);
        sock_release(mem_sock);
        mem_sock = NULL;
        return ret;
    }

    pr_info("MemDumper: Connected to %pI4:%u\n", &saddr.sin_addr.s_addr, remote_port);
    return 0;
}

/* Close and release TCP socket */
static void close_remote(void)
{
    if (mem_sock) {
        sock_release(mem_sock);
        mem_sock = NULL;
    }
}

/* send all bytes in buffer over mem_sock using kernel_sendmsg
 * returns 0 on success, negative errno on failure
 */

static int tcp_send_all(const char *buffer, size_t length)
{
    size_t total = 0;
    int retry_count = 0;
    
    while (total < length) {
        struct kvec iov;
        struct msghdr msg;
        int sent;
        size_t remain = length - total;
        size_t chunk = (remain > (size_t)MAX_RW_COUNT) ? (size_t)MAX_RW_COUNT : remain;

        memset(&msg, 0, sizeof(msg));
        iov.iov_base = (void *)(buffer + total);
        iov.iov_len = chunk;

        sent = kernel_sendmsg(mem_sock, &msg, &iov, 1, chunk);
        
        if (sent < 0) {
            // Проверяем нужно ли retry
            if (sent == -EAGAIN || sent == -EWOULDBLOCK) {
                if (retry_count++ < 10) {
                    msleep(100); // Пауза 100ms
                    continue;
                }
            }
            pr_err("MemDumper: kernel_sendmsg failed: %d at total=%zu\n", sent, total);
            return sent;
        }
        
        if (sent == 0) {
            pr_err("MemDumper: kernel_sendmsg returned 0 (remote closed?)\n");
            return -EIO;
        }

        total += (size_t)sent;
        retry_count = 0; // Сбрасываем счетчик retry после успешной отправки
    }

    return 0;
}


/* ---------- File write helpers (kept versioned) ---------- */

/* Write all bytes to opened file (handles large files via chunking).
 * Returns 0 on success, negative errno on failure.
 */

static int file_write_all(const char *buffer, size_t length)
{
    size_t total = 0;
    ssize_t ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(KERNEL_DS);
#endif

    while (total < length) {
        size_t remain = length - total;
        
        // КРИТИЧЕСКИ ВАЖНО: ограничиваем размер chunk'а 2GB
        size_t chunk = remain;
        if (chunk > (size_t)MAX_RW_COUNT) {
            chunk = (size_t)MAX_RW_COUNT;
        }
        
        // Также проверяем чтобы не превысить 2GB границу в file_position
        if (file_position > MAX_RW_COUNT && 
            file_position + chunk > MAX_RW_COUNT * 2) {
            // Дополнительная страховка
            chunk = MAX_RW_COUNT - (file_position % MAX_RW_COUNT);
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        ret = kernel_write(output_file, buffer + total, chunk, &file_position);
#else
        ret = vfs_write(output_file, buffer + total, chunk, &file_position);
#endif

        if (ret < 0) {
            pr_err("MemDumper: file write error %zd at pos %llu, chunk: %zu\n", 
                  ret, (unsigned long long)file_position, chunk);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
            set_fs(old_fs);
#endif
            return (int)ret;
        }
        
        if (ret == 0) {
            pr_err("MemDumper: file write returned 0 at pos %llu\n", 
                  (unsigned long long)file_position);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
            set_fs(old_fs);
#endif
            return -EIO;
        }
        
        total += (size_t)ret;
        
        // Отладочная информация
        if (total % (100 * 1024 * 1024) == 0) {
            pr_info("MemDumper: Written %zu MB, position: %llu\n",
                   total / (1024 * 1024), (unsigned long long)file_position);
        }
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    set_fs(old_fs);
#endif

    return 0;
}

/* Unified "output" wrapper: either send to TCP or write to file */
static int output_write(const char *buffer, size_t length)
{
    if (use_tcp) {
        if (!mem_sock)
            return -ENOTCONN;
        return tcp_send_all(buffer, length);
    } else {
        if (!output_file)
            return -EBADF;
        return file_write_all(buffer, length);
    }
}

/* --------- Protection --------- */

static void protect_from_oom(void)
{
    struct file *oom_file;
    char oom_value[] = "-1000\n";
    loff_t pos = 0;
    ssize_t ret;
    
    // Пробуем modern oom_score_adj
    oom_file = filp_open("/proc/self/oom_score_adj", O_WRONLY, 0);
    if (IS_ERR(oom_file)) {
        pr_info("MemDumper: oom_score_adj not available, trying oom_adj...\n");
        
        // Fallback на старый oom_adj
        oom_file = filp_open("/proc/self/oom_adj", O_WRONLY, 0);
        if (IS_ERR(oom_file)) {
            pr_info("MemDumper: OOM protection not available\n");
            return;
        }
        strcpy(oom_value, "-17\n"); // Старое значение
    }
    
    // Записываем значение
    ret = kernel_write(oom_file, oom_value, strlen(oom_value), &pos);
    if (ret < 0) {
        pr_info("MemDumper: Failed to set OOM value: %zd\n", ret);
    } else {
        pr_info("MemDumper: OOM protection set to %s", oom_value);
    }
    
    filp_close(oom_file, NULL);
}

static void setup_process_protection(void)
{
    // 1. Высокий приоритет
    set_user_nice(current, -20);
    
    // 2. Защита от заморозки
    current->flags |= PF_NOFREEZE;
    
    // 3. Защита от OOM Killer
    protect_from_oom();
    
    pr_info("MemDumper: Process protection complete\n");
}

static void restore_process_settings(void)
{
    // Только восстанавливаем то, что меняли напрямую
    set_user_nice(current, 0);
    current->flags &= ~PF_NOFREEZE;
    
    pr_info("MemDumper: Basic settings restored\n");
    
    // OOM настройки восстановятся автоматически при завершении процесса
}

/* ---------- Memory dump logic (page loop) ---------- */

static int dump_memory_page_safe(unsigned long pfn, char *scratch_buf)
{
    struct page *page;
    void *mapped_address = NULL;
    
    // Всегда начинаем с заполнения нулями
    memset(scratch_buf, 0, PAGE_SIZE);
    
    // Проверка 1: PFN находится в разумных пределах
    if (pfn > (1024 * 1024 * 1024 / PAGE_SIZE)) { // > 1GB в PFN
        return 0;
    }
    
    // Проверка 2: Валидность PFN
    if (!pfn_valid(pfn)) {
        return 0;
    }
    
    // Проверка 3: Получение структуры page
    page = pfn_to_page(pfn);
    if (!page) {
        return 0;
    }
    
    // Проверка 4: Страница зарезервирована или особенная
    if (PageReserved(page)) {
        return 0;
    }

    // Пытаемся отобразить страницу
    mapped_address = kmap_atomic(page);
    if (!mapped_address) {
        return 0;
    }

    // Безопасное копирование - используем простой memcpy
    // В ядре Linux нет try-catch, поэтому полагаемся на проверки выше
    memcpy(scratch_buf, mapped_address, PAGE_SIZE);

    kunmap_atomic(mapped_address);
    return 0;
}


static void create_memory_dump(void)
{
    char *page_scratch;
    int error_count = 0;
    int ret;
    struct sysinfo info;
    unsigned long pfn;
    unsigned long max_pfn;
    unsigned long total_pages_dumped = 0;

    pr_info("MemDumper: Module loaded. Beginning dump process...\n");

    setup_process_protection();
    
    si_meminfo(&info);
    pr_info("MemDumper: Total RAM: %lu MB\n", info.totalram * info.mem_unit / 1024 / 1024);

    if (strncmp(dump_path, "tcp:", 4) == 0) {
        ret = parse_tcp_path(dump_path);
        if (ret != 0) {
            pr_err("MemDumper: Invalid tcp path format. Use tcp:IP:PORT or use a fs path\n");
            return;
        }
        pr_info("MemDumper: Will stream memory to %pI4:%u\n", &remote_addr_be, remote_port);
    } else {
        use_tcp = false;
        pr_info("MemDumper: Will write dump to file %s\n", dump_path);
    }

    pr_info("MemDumper: Starting memory dump to %s\n", dump_path);
    
    // ТОЧНЫЙ расчет max_pfn на основе общего объема памяти
    max_pfn = (info.totalram * info.mem_unit) / PAGE_SIZE;
    pr_info("MemDumper: Exact max_pfn: %lu (Total RAM: %lu MB, Page size: %lu)\n", 
        max_pfn, (info.totalram * info.mem_unit) / 1024 / 1024, PAGE_SIZE);

    // Initialize output
    if (!use_tcp) {
        output_file = filp_open(dump_path, O_CREAT | O_WRONLY | O_TRUNC | O_LARGEFILE, 0644);
        if (IS_ERR(output_file)) {
            pr_err("MemDumper: FATAL: Cannot open output file! Err=%ld\n", PTR_ERR(output_file));
            output_file = NULL;
            return;
        }
        file_position = 0;
    } else {
        ret = connect_to_remote();
        if (ret < 0) {
            pr_err("MemDumper: cannot connect to remote, aborting dump\n");
            return;
        }
    }

    page_scratch = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!page_scratch) {
        pr_err("MemDumper: cannot allocate scratch buffer\n");
        goto cleanup;
    }

    // --- САМЫЙ БЕЗОПАСНЫЙ МЕТОД: Обход с максимальной защитой ---
    pr_info("MemDumper: Iterating over PFNs with maximum protection...\n");

    for (pfn = 0; pfn < max_pfn; pfn++) {
        // Проверяем прерывание
        if (fatal_signal_pending(current) || signal_pending(current)) {
            pr_info("MemDumper: Interrupted at PFN %lu\n", pfn);
            break;
        }

        // ОЧЕНЬ осторожная проверка валидности страницы
        if (!pfn_valid(pfn)) {
            // Для невалидных страниц записываем нули
            memset(page_scratch, 0, PAGE_SIZE);
            goto safe_write;
        }

        // Дампим страницу с обработкой возможных ошибок
        if (dump_memory_page_safe(pfn, page_scratch) != 0) {
            error_count++;
            continue;
        }

safe_write:
        // Записываем данные (нули или реальные данные)
        if (output_write(page_scratch, PAGE_SIZE) != 0) {
            error_count++;
        } else {
            total_pages_dumped++;
        }

        if ((total_pages_dumped % 100000) == 0) {
            pr_info("MemDumper: Pages dumped: %lu\n", total_pages_dumped);
        }
    }

    pr_info("MemDumper: Dump completed. Total pages dumped: %lu, Errors: %d\n", 
           total_pages_dumped, error_count);
    pr_info("MemDumper: Total size: %lu MB\n", 
           (total_pages_dumped * PAGE_SIZE) / 1024 / 1024);
    
    kfree(page_scratch);

cleanup:
    if (output_file) {
        filp_close(output_file, NULL);
        output_file = NULL;
    }
    if (mem_sock) {
        close_remote();
    }
    restore_process_settings();
}

/* ---------- Module init/exit ---------- */

static int __init mem_dumper_init(void)
{
    int parse_ret;

    pr_info("MemDumper: Module loaded. Beginning dump process...\n");

    if (strncmp(dump_path, "tcp:", 4) == 0) {
        parse_ret = parse_tcp_path(dump_path);
        if (parse_ret != 0) {
            pr_err("MemDumper: Invalid tcp path format. Use tcp:IP:PORT or use a fs path\n");
            return -EINVAL;
        }
        pr_info("MemDumper: Will stream memory to %pI4:%u\n", &remote_addr_be, remote_port);
    } else {
        use_tcp = false;
        pr_info("MemDumper: Will write dump to file %s\n", dump_path);
    }

    create_memory_dump();
    return 0;
}

static void __exit mem_dumper_exit(void)
{
    pr_info("MemDumper: Module unloaded.\n");
    if (mem_sock)
        close_remote();
    if (output_file)
        filp_close(output_file, NULL);
}

module_init(mem_dumper_init);
module_exit(mem_dumper_exit);
