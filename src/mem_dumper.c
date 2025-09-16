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

// RESTORE НЕ НУЖЕН для /proc подхода!
static void restore_process_settings(void)
{
    // Только восстанавливаем то, что меняли напрямую
    set_user_nice(current, 0);
    current->flags &= ~PF_NOFREEZE;
    
    pr_info("MemDumper: Basic settings restored\n");
    
    // OOM настройки восстановятся автоматически при завершении процесса
}

/* ---------- Memory dump logic (page loop) ---------- */

static int dump_memory_page(unsigned long pfn, char *scratch_buf)
{
    struct page *page;
    void *mapped_address;
    int ret;

    // Безопасная проверка существования страницы
    if (!pfn_valid(pfn))
        return -1;
        
    page = pfn_to_page(pfn);
    
    // Пробуем маппить с обработкой ошибок
    mapped_address = kmap_atomic(page);
    if (!mapped_address) {
        // Страница существует, но не может быть маппирована
        // Заполняем нулями вместо реальных данных
        memset(scratch_buf, 0, PAGE_SIZE);
    } else {
        // Успешно маппим - копируем реальные данные
        memcpy(scratch_buf, mapped_address, PAGE_SIZE);
        kunmap_atomic(mapped_address);
    }

    // Всегда отправляем данные (даже если это нули)
    ret = output_write(scratch_buf, PAGE_SIZE);
    if (ret != 0) {
        return -1;
    }

    return 0;
}


static void create_memory_dump(void)
{
    unsigned long pfn;
    unsigned long max_pfn;
    char *page_scratch;
    int error_count = 0;
    struct page *page;
    int ret;
    struct sysinfo info;

    pr_info("MemDumper: Module loaded. Beginning dump process...\n");

    // ЗАЩИТА ПРОЦЕССА
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
    
    max_pfn = totalram_pages() + totalhigh_pages();
    pr_info("MemDumper: totalram_pages = %lu\n", totalram_pages());
    pr_info("MemDumper: totalhigh_pages = %lu\n", totalhigh_pages());  
    pr_info("MemDumper: Max PFN: %lu\n", max_pfn);

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

    for (pfn = 0; pfn < max_pfn; pfn++) {
        // Проверяем различные причины прерывания
        if (fatal_signal_pending(current)) {
            pr_info("MemDumper: Fatal signal pending at PFN %lu\n", pfn);

            // Простая проверка каких сигналов ожидают
            if (sigismember(&current->pending.signal, SIGTERM)) {
                pr_info("MemDumper: SIGTERM pending\n");
            }
            if (sigismember(&current->pending.signal, SIGKILL)) {
                pr_info("MemDumper: SIGKILL pending\n");
            }
            break;
        }
    
        //if (kthread_should_stop()) {
        //    pr_info("MemDumper: Kthread stop requested at PFN %lu\n", pfn);
        //    break;
        //}
    
        if (current->flags & PF_EXITING) {
            pr_info("MemDumper: Process exiting at PFN %lu\n", pfn);
            break;
        }
    
        if (signal_pending(current)) {
            pr_info("MemDumper: Signal pending at PFN %lu\n", pfn);
            break;
        }
            
        if (!pfn_valid(pfn))
            continue;
            
        page = pfn_to_page(pfn);
        
        if (PageReserved(page)) {
            continue;
        }

        if (dump_memory_page(pfn, page_scratch) != 0) {
            error_count++;
        }

        if ((pfn % 100000) == 0) {
            unsigned int percent = (pfn * 100) / max_pfn;
            pr_info("MemDumper: PFN %lu/%lu (%u%%)\n", 
                   pfn, max_pfn, percent);
        }
    }
    
    if (pfn < max_pfn) {
        pr_info("MemDumper: Dump interrupted at PFN %lu/%lu (%lu pages remaining)\n", 
            pfn, max_pfn, max_pfn - pfn);
    } else {
        pr_info("MemDumper: Dump completed successfully\n");
    }

    kfree(page_scratch);

cleanup:
    if (output_file) {
        filp_close(output_file, NULL);
        output_file = NULL;
    }
    if (mem_sock) {
        close_remote();
    }
    
    // ВОССТАНОВЛЕНИЕ НАСТРОЕК
    restore_process_settings();

    pr_info("MemDumper: Dump complete. Errors: %d\n", error_count);
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
