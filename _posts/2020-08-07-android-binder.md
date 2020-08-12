---
layout: post
title: 'Android Binder'
date: 2020-08-07
author: 'withparadox2'
catalog: true
tags:
  - Android
---

# 1 Service Manager 成为 Context Manager

Binder 初始化及 Service Manager 成为 Context Manager。 

## 1.1 binder_init
```c
// kernel/drivers/android/binder.c
static const struct file_operations binder_fops = {
  .owner = THIS_MODULE,
  .poll = binder_poll,
  .unlocked_ioctl = binder_ioctl,
  .mmap = binder_mmap,
  .open = binder_open,
  .flush = binder_flush,
  .release = binder_release,
};

static struct miscdevice binder_miscdev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "binder",
  .fops = &binder_fops
};

static int __init binder_init(void)
{
  int ret;

  binder_deferred_workqueue = create_singlethread_workqueue("binder");
  if (!binder_deferred_workqueue)
    return -ENOMEM;

  binder_debugfs_dir_entry_root = debugfs_create_dir("binder", NULL);
  if (binder_debugfs_dir_entry_root)
    binder_debugfs_dir_entry_proc = debugfs_create_dir("proc",
             binder_debugfs_dir_entry_root);
  ret = misc_register(&binder_miscdev);
  if (binder_debugfs_dir_entry_root) {
    ...
  }
  return ret;
}

device_initcall(binder_init);
MODULE_LICENSE("GPL v2");
```
当内核加载驱动时便会执行 device_initcall 所传入的方法（binder_init）进行初始化。在该方法中最重要的一步便是调用 mis_register 进行注册，而且 binder_miscdev 也指定了设备的名字为 binder 以及一个包含文件操作方法的结构体 binder_fops。后面用户便可以通过系统调用如 open、ioctl 打开并与驱动进行交互了。

## 1.2 main
```c
// frameworks/native/cmds/servicemanager/service_manager.c
int main(int argc, char **argv)
{
    struct binder_state *bs;

    // 打开 binder 驱动，指定内存大小为 128kb，见 1.3
    bs = binder_open(128*1024);
    if (!bs) {
        ALOGE("failed to open binder driver\n");
        return -1;
    }

    // 成为 Context Manager，见 1.4
    if (binder_become_context_manager(bs)) {
        ALOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }
    ...
    // 进入循环，等待请求，见 1.5
    binder_loop(bs, svcmgr_handler);

    return 0;
}
```

## 1.3 binder_open

```c
// kernel/drivers/android/binder.c
// mapsize = 128*1024
struct binder_state *binder_open(size_t mapsize)
{
    struct binder_state *bs;
    struct binder_version vers;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }
    // 会执行 binder 驱动里的 binder_open，返回的 fd 为文件句柄，用来和 binder 进行通信，见 1.3.1
    bs->fd = open("/dev/binder", O_RDWR);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open device (%s)\n",
                strerror(errno));
        goto fail_open;
    }

    // 检测和 binder 驱动的版本是否相同，见 1.3.2
    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        fprintf(stderr, "binder: kernel driver version (%d) differs from user space version (%d)\n", vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;
    }

    bs->mapsize = mapsize;
    // 见 1.3.3
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0);
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n", strerror(errno));
        goto fail_map;
    }

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
}
```

### 1.3.1 binder_open

```c
// kernel/drivers/android/binder.c
static int binder_open(struct inode *nodp, struct file *filp)
{
  struct binder_proc *proc;
  proc = kzalloc(sizeof(*proc), GFP_KERNEL);
  if (proc == NULL)
    return -ENOMEM;

  // current 为发起系统调用的进程
  get_task_struct(current);
  proc->tsk = current;
  INIT_LIST_HEAD(&proc->todo);
  init_waitqueue_head(&proc->wait);
  proc->default_priority = task_nice(current);
  mutex_lock(&binder_lock);
  binder_stats_created(BINDER_STAT_PROC);
  hlist_add_head(&proc->proc_node, &binder_procs);
  proc->pid = current->group_leader->pid;
  // ???
  INIT_LIST_HEAD(&proc->delivered_death);
  // 保存 proc，后面 mmap 或 ioctl 时可取出
  filp->private_data = proc;
  mutex_unlock(&binder_lock);
  ...
  return 0;
}
```
每个进程在与驱动交互之前都会进行 open 和 mmap 操作，binder 驱动会在内核为其创建一个 proc 对象，并进行初始化，之后会将 proc 对象记录在 binder_procs 这个列表里。filp 为 file pointer，在调用 open 之前，内核会将 filp->private_data 置为 NULL，该字段可以用来保存数据，以便在后面取出。

其中 proc->todo 用来保存待处理的任务，proc->wait 则用来进行休眠。当没有任务时服务提供者就会休眠，等待其他线程调用 wake_up_interruptible(wait) 来唤醒。后面还将出现 thread 对象，它也包含 todo 和 wait 两个变量。

### 1.3.2 ioctl (获取 binder 版本)
```c
// kernel/drivers/android/binder.c
// cmd = BINDER_VERSION = _IOWR('b', 9, struct binder_version)
// arg = &vers
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret;
  // 取出在 binder_open 时保存的 proc
  struct binder_proc *proc = filp->private_data;
  struct binder_thread *thread;
  // 参数 arg 所指向内容的大小
  unsigned int size = _IOC_SIZE(cmd);
  void __user *ubuf = (void __user *)arg;
  
  ...

  switch (cmd) {
  case BINDER_VERSION:
    if (size != sizeof(struct binder_version)) {
      ret = -EINVAL;
      goto err;
    }
    if (put_user(BINDER_CURRENT_PROTOCOL_VERSION, 
      &((struct binder_version *)ubuf)->protocol_version)) {
      ret = -EINVAL;
      goto err;
    }
    break;
  ...
  }
  ret = 0;
err:
  ...
  return ret;
}
```
arg 是一个指向位于用户空间的 struct binder_version 的指针，而所指向内容的大小信息保存在 cmd 中，通过_IOC_SIZE 可以解析出来。

由于 arg 指向的地址位于用户空间，不能直接操作，所以这里通过 put_user 将版本信息保存到结构体的 protocol_version 字段里。

### 1.3.3 binder_mmap
```c
// kernel/drivers/android/binder.c
// vma 包含用户空间的虚拟内存分配信息
static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
  int ret;
  // 内核空间虚拟内存分配信息
  struct vm_struct *area;
  // 取出 proc
  struct binder_proc *proc = filp->private_data;
  const char *failure_string;
  struct binder_buffer *buffer;
 
  // 保证最大分配不超过 4Mb，这里请求时只有 128Kb
  if ((vma->vm_end - vma->vm_start) > SZ_4M)
    vma->vm_end = vma->vm_start + SZ_4M;

  if (vma->vm_flags & FORBIDDEN_MMAP_FLAGS) {
    ret = -EPERM;
    failure_string = "bad vm_flags";
    goto err_bad_arg;
  }
  vma->vm_flags = (vma->vm_flags | VM_DONTCOPY) & ~VM_MAYWRITE;

  if (proc->buffer) {
    ret = -EBUSY;
    failure_string = "already mapped";
    goto err_already_mapped;
  }

  area = get_vm_area(vma->vm_end - vma->vm_start, VM_IOREMAP);
  if (area == NULL) {
    ret = -ENOMEM;
    failure_string = "get_vm_area";
    goto err_get_vm_area_failed;
  }
  // 指向内核空间分配的虚拟内存起始地址
  proc->buffer = area->addr;
  proc->user_buffer_offset = vma->vm_start - (uintptr_t)proc->buffer;

  // 分配内存用来保存包含物理内存页面信息的数组，数组大小即为页面数量
  proc->pages = kzalloc(sizeof(proc->pages[0]) * ((vma->vm_end - vma->vm_start) / PAGE_SIZE), GFP_KERNEL);
  if (proc->pages == NULL) {
    ret = -ENOMEM;
    failure_string = "alloc page array";
    goto err_alloc_pages_failed;
  }
  proc->buffer_size = vma->vm_end - vma->vm_start;

  vma->vm_ops = &binder_vm_ops;
  vma->vm_private_data = proc;
  
  // 先分配 1 个页面的物理内存，见 1.3.3.1
  if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
    ret = -ENOMEM;
    failure_string = "alloc small buf";
    goto err_alloc_small_buf_failed;
  }
  // 不进行初始化???
  buffer = proc->buffer;
  INIT_LIST_HEAD(&proc->buffers);
  // 将 buffer 加入到 proc->buffers 列表中
  list_add(&buffer->entry, &proc->buffers);
  buffer->free = 1;
  // 将该 buffer 加入到未使用的 buffer 树中，见 1.3.3.2
  binder_insert_free_buffer(proc, buffer);
  // 用于异步请求的 buffer 只有一半大小，具体如何使用???
  proc->free_async_space = proc->buffer_size / 2;
  barrier();
  proc->files = get_files_struct(current);
  proc->vma = vma;

  return 0;

err_alloc_small_buf_failed:
  kfree(proc->pages);
  proc->pages = NULL;
err_alloc_pages_failed:
  vfree(proc->buffer);
  proc->buffer = NULL;
err_get_vm_area_failed:
err_already_mapped:
err_bad_arg:
  printk(KERN_ERR "binder_mmap: %d %lx-%lx %s failed %d\n",
         proc->pid, vma->vm_start, vma->vm_end, failure_string, ret);
  return ret;
}

```
调用 get_vm_area 在内核空间分配一段虚拟内存，最大不超过 4Mb。由于用户空间和内核空间分配的这块虚拟内存指向同一处物理内存，因此知道这二者之差便可以将其进行地址转换。例如，如果知道内核空间地址为 addr1，那么用户空间的地址便可通过简单的加法计算出来 proc->user_buffer_offset + addr1。

这里有个问题，buffer 是一个指向 struct binder_buffer 的指针，而 proc->buffer 指向的是一段连续的虚拟内存，为何可以直接将 proc->buffer 赋值给 buffer 而不用初始化？

事实上，在 binder_update_page_range 中已经分配了一段大小为一个页面的物理内存，并且初始化为 0。buffer 的一个应用是通过 binder_buffer_size 计算大小，这一步并不需要多余的初始化：

```c
// kernel/drivers/android/binder.c
static size_t binder_buffer_size(struct binder_proc *proc,
         struct binder_buffer *buffer)
{
  if (list_is_last(&buffer->entry, &proc->buffers))
    // 用整段 buffer 的结束地址减去 buffer 结构体的结束地址
    return proc->buffer + proc->buffer_size - (void *)buffer->data;
  else
    return (size_t)list_entry(buffer->entry.next,
      struct binder_buffer, entry) - (size_t)buffer->data;
}
```
buffer 是连续的。buffer 指向的内存包含了 buffer 的结构体，所以 buffer 的有效内存大小则是下一个 buffer 的起始地址减去当前 buffer 的结构体的结束地址，而 buffer->data 是一个位于结构体末尾的 8 位数组，因此 buffer->data 便可表示结构体的结束地址。

```c
struct binder_buffer {
  struct list_head entry;
  struct rb_node rb_node; 
  unsigned free:1;
  unsigned allow_user_free:1;
  unsigned async_transaction:1;
  unsigned debug_id:29;

  struct binder_transaction *transaction;

  struct binder_node *target_node;
  size_t data_size;
  size_t offsets_size;
  uint8_t data[0];
};
```

每个 buffer 包含一个 entry 字段，加入到 proc->buffers 列表中的也是 entry 字段。list_entry 定义如下：

```c
#define list_entry(ptr, type, member) \
  container_of(ptr, type, member)
 
#define container_of(ptr, type, member) ({\
  const typeof( ((type *)0)->member ) *__mptr = (ptr); \  
  (type *)( (char *)__mptr - offsetof(type,member) );}) \
```
知道 member 和指向 member 的指针 ptr，便可以计算出指向包含 member 的结构体 type 的指针。这种操作在其他内核数据结构中也常见，包括红黑树。

#### 1.3.3.1 binder_update_page_range

```c++
// kernel/drivers/android/binder.c
// allocate = 1 当为 0 时表示释放物理内存
// start = proc->buffer
// end = proc->buffer + PAGE_SIZE
static int binder_update_page_range(struct binder_proc *proc, int allocate,
            void *start, void *end,
            struct vm_area_struct *vma)
{
  void *page_addr;
  unsigned long user_page_addr;
  struct vm_struct tmp_area;
  struct page **page;
  // 描述进程的虚拟地址空间，位于用户空间
  struct mm_struct *mm;

  if (end <= start)
    return 0;

  if (vma)
    mm = NULL;
  else
    mm = get_task_mm(proc->tsk);

  if (mm) {
    down_write(&mm->mmap_sem);
    vma = proc->vma;
  }

  if (allocate == 0)
    goto free_range;

  if (vma == NULL) {
    printk(KERN_ERR "binder: %d: binder_alloc_buf failed to "
           "map pages in userspace, no vma\n", proc->pid);
    goto err_no_vma;
  }

  for (page_addr = start; page_addr < end; page_addr += PAGE_SIZE) {
    int ret;
    struct page **page_array_ptr;
    // 这里取出第 0 个页面
    page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];

    BUG_ON(*page);
    *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (*page == NULL) {
      printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
             "for page at %p\n", proc->pid, page_addr);
      goto err_alloc_page_failed;
    }
    // 内核虚拟内存页面起始和大小描述
    tmp_area.addr = page_addr;
    tmp_area.size = PAGE_SIZE + PAGE_SIZE /* guard page? */;
    // 物理内存页面描述
    page_array_ptr = page;
    // 将内核虚拟内存页面和物理内存页面进行映射
    ret = map_vm_area(&tmp_area, PAGE_KERNEL, &page_array_ptr);
    if (ret) {
      printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
             "to map page at %p in kernel\n",
             proc->pid, page_addr);
      goto err_map_kernel_failed;
    }
    // 用户虚拟内存页面起始地址
    user_page_addr =
      (uintptr_t)page_addr + proc->user_buffer_offset;
    // 将用户虚拟内存页面和物理内存页面进行映射
    ret = vm_insert_page(vma, user_page_addr, page[0]);
    if (ret) {
      printk(KERN_ERR "binder: %d: binder_alloc_buf failed "
             "to map page at %lx in userspace\n",
             proc->pid, user_page_addr);
      goto err_vm_insert_page_failed;
    }
    /* vm_insert_page does not seem to increment the refcount */
  }
  if (mm) {
    up_write(&mm->mmap_sem);
    mmput(mm);
  }
  return 0;

free_range:
  for (page_addr = end - PAGE_SIZE; page_addr >= start;
       page_addr -= PAGE_SIZE) {
    page = &proc->pages[(page_addr - proc->buffer) / PAGE_SIZE];
    if (vma)
      // 仅仅释放用户空间指定的页面???
      zap_page_range(vma, (uintptr_t)page_addr +
        proc->user_buffer_offset, PAGE_SIZE, NULL);
err_vm_insert_page_failed:
    unmap_kernel_range((unsigned long)page_addr, PAGE_SIZE);
err_map_kernel_failed:
    __free_page(*page);
    *page = NULL;
err_alloc_page_failed:
    ;
  }
err_no_vma:
  if (mm) {
    up_write(&mm->mmap_sem);
    mmput(mm);
  }
  return -ENOMEM;
}
```
问题：allocate 等于 0 的情况？

#### 1.3.3.2 binder_insert_free_buffer

```c
// kernel/drivers/android/binder.c
static void binder_insert_free_buffer(struct binder_proc *proc,
              struct binder_buffer *new_buffer)
{
  struct rb_node **p = &proc->free_buffers.rb_node;
  struct rb_node *parent = NULL;
  struct binder_buffer *buffer;
  size_t buffer_size;
  size_t new_buffer_size;

  BUG_ON(!new_buffer->free);

  // 计算计划插入的 buffer 有效空间大小
  new_buffer_size = binder_buffer_size(proc, new_buffer);

  binder_debug(BINDER_DEBUG_BUFFER_ALLOC,
         "binder: %d: add free buffer, size %zd, "
         "at %p\n", proc->pid, new_buffer_size, new_buffer);
  // 红黑树的标准遍历法，无甚可说
  while (*p) {
    parent = *p;
    buffer = rb_entry(parent, struct binder_buffer, rb_node);
    BUG_ON(!buffer->free);

    buffer_size = binder_buffer_size(proc, buffer);

    if (new_buffer_size < buffer_size)
      p = &parent->rb_left;
    else
      p = &parent->rb_right;
  }
  // 红黑树的标准插入法
  rb_link_node(&new_buffer->rb_node, parent, p);
  rb_insert_color(&new_buffer->rb_node, &proc->free_buffers);
}
```
## 1.4 binder_become_context_manager

```c
// frameworks/native/cmds/servicemanager/binder.c
int binder_become_context_manager(struct binder_state *bs)
{
    // 见 1.4.1
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}
```

### 1.4.1 ioctl (BINDER_SET_CONTEXT_MGR)

```c
// kernel/drivers/android/binder.c

static struct binder_node *binder_context_mgr_node;
static uid_t binder_context_mgr_uid = -1;

// cmd = BINDER_SET_CONTEXT_MGR = _IOW('b', 7, int)
// arg = 指向 4 字节内存，内容为 0
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret;
  struct binder_proc *proc = filp->private_data;
  struct binder_thread *thread;
  // arg 指向内存大小，这里大小为 4，内容为 0
  unsigned int size = _IOC_SIZE(cmd);
  void __user *ubuf = (void __user *)arg;

  mutex_lock(&binder_lock);
  ...
  switch (cmd) {
  case BINDER_SET_CONTEXT_MGR:
    if (binder_context_mgr_node != NULL) {
      printk(KERN_ERR "binder: BINDER_SET_CONTEXT_MGR already set\n");
      ret = -EBUSY;
      goto err;
    }
    ret = security_binder_set_context_mgr(proc->tsk);
    if (ret < 0)
      goto err;
    // binder_context_mgr_uid 默认为-1
    if (binder_context_mgr_uid != -1) {
      if (binder_context_mgr_uid != current->cred->euid) {
        printk(KERN_ERR "binder: BINDER_SET_"
               "CONTEXT_MGR bad uid %d != %d\n",
               current->cred->euid,
               binder_context_mgr_uid);
        ret = -EPERM;
        goto err;
      }
    } else
      binder_context_mgr_uid = current->cred->euid;
    // 创建一个 binder_node，见 1.4.1.1
    binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
    if (binder_context_mgr_node == NULL) {
      ret = -ENOMEM;
      goto err;
    }
    // 将各种引用加 1，干什么用？？？
    binder_context_mgr_node->local_weak_refs++;
    binder_context_mgr_node->local_strong_refs++;
    binder_context_mgr_node->has_strong_ref = 1;
    binder_context_mgr_node->has_weak_ref = 1;
    break;
  }
  ret = 0;
err:
  ...
  return ret;
}
```

#### 1.4.1.1 binder_new_node
```c
// kernel/drivers/android/binder.c
// ptr = NULL ？？？
// cookie = NULL 用来存储对象的实际指针
static struct binder_node *binder_new_node(struct binder_proc *proc,
             void __user *ptr,
             void __user *cookie)
{
  struct rb_node **p = &proc->nodes.rb_node;
  struct rb_node *parent = NULL;
  struct binder_node *node;

  while (*p) {
    parent = *p;
    node = rb_entry(parent, struct binder_node, rb_node);

    if (ptr < node->ptr)
      p = &(*p)->rb_left;
    else if (ptr > node->ptr)
      p = &(*p)->rb_right;
    else
      // 表示查到了，不再进行创建
      return NULL;
  }

  node = kzalloc(sizeof(*node), GFP_KERNEL);
  if (node == NULL)
    return NULL;
  binder_stats_created(BINDER_STAT_NODE);
  // 将新创建的 node 插入红黑树中，其父节点为 parent
  rb_link_node(&node->rb_node, parent, p);
  rb_insert_color(&node->rb_node, &proc->nodes);
  // 每次创建 debug_id 加 1
  node->debug_id = ++binder_last_id;
  node->proc = proc;
  node->ptr = ptr;
  node->cookie = cookie;
  node->work.type = BINDER_WORK_NODE;
  INIT_LIST_HEAD(&node->work.entry);
  INIT_LIST_HEAD(&node->async_todo);
  binder_debug(BINDER_DEBUG_INTERNAL_REFS,
         "binder: %d:%d node %d u%p c%p created\n",
         proc->pid, current->pid, node->debug_id,
         node->ptr, node->cookie);
  return node;
}
```
该方法创建一个新的 binder_node，插入到 proc->nodes 中，然后进行初始化。

## 1.5 binder_loop

```c
// frameworks/native/cmds/servicemanager/binder.c
// bs = binder_open 的返回值
// func = svcmgr_handler
void binder_loop(struct binder_state *bs, binder_handler func)
{
    int res;
    struct binder_write_read bwr;
    uint32_t readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;

    readbuf[0] = BC_ENTER_LOOPER;
    // 见 1.5.1
    binder_write(bs, readbuf, sizeof(uint32_t));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;

        // 见 1.5.2
        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }

        // 见 1.5.3
        res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
        if (res == 0) {
            ALOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}
```

### 1.5.1 binder_write & ioctl (BINDER_SET_CONTEXT_MGR#BC_ENTER_LOOPER)
```c
// frameworks/native/cmds/servicemanager/binder.c
// data = readbuf，大小为 32 的 4 字节数组，其中 readbuf[0] = BC_ENTER_LOOPER
// len = 4
int binder_write(struct binder_state *bs, void *data, size_t len)
{
    struct binder_write_read bwr;
    int res;

    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    // 见下面代码
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}
```

```c
// kernel/drivers/android/binder.c
/*
cmd = BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read)
arg = 指向 binder_write_read 结构体，内容如下：
{
  write_size: 4,
  write_consumed: 0,
  write_buffer: 大小 32 的数组，[BC_ENTER_LOOPER, ... ],
  read_size: 0,
  read_consumed: 0,
  read_buffer: 0
}
*/
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret;
  struct binder_proc *proc = filp->private_data;
  struct binder_thread *thread;
  unsigned int size = _IOC_SIZE(cmd);
  void __user *ubuf = (void __user *)arg;
  ...
  mutex_lock(&binder_lock);
  // 查找或创建当前线程的结构体，见 1.5.1.1
  thread = binder_get_thread(proc);
  if (thread == NULL) {
    ret = -ENOMEM;
    goto err;
  }

  switch (cmd) {
  case BINDER_WRITE_READ: {
    struct binder_write_read bwr;
    if (size != sizeof(struct binder_write_read)) {
      ret = -EINVAL;
      goto err;
    }
    // 将用户空间的数据拷贝到内核空间，但是 bwr.write_buffer 目前依然指向用户空间 
    if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    // write_size 为 4
    if (bwr.write_size > 0) {
      // 见 1.5.1.2
      ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
      if (ret < 0) {
        // 如果出错，则设置 read_consumed 为 0，意即驱动没有写入任何数据，返回
        bwr.read_consumed = 0;
        if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
          ret = -EFAULT;
        goto err;
      }
    }
    
    // bwr.read_size 为 0，跳过
    if (bwr.read_size > 0) {
      ...
    }
    
    // 把 bwr 拷贝到用户空间，准备返回到用户空间
    if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    break;
  }
  }
  ret = 0;
err:
  if (thread)
    thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
  mutex_unlock(&binder_lock);
  ...
  return ret;
}
```
执行完成后，返回到 1.5，继续执行 for 循环里面的内容。

##### 1.5.1.1 binder_get_thread
```c
// kernel/drivers/android/binder.c
static struct binder_thread *binder_get_thread(struct binder_proc *proc)
{
  struct binder_thread *thread = NULL;
  struct rb_node *parent = NULL;
  struct rb_node **p = &proc->threads.rb_node;

  while (*p) {
    parent = *p;
    thread = rb_entry(parent, struct binder_thread, rb_node);

    if (current->pid < thread->pid)
      p = &(*p)->rb_left;
    else if (current->pid > thread->pid)
      p = &(*p)->rb_right;
    else
      break;
  }
  // 没有找到，则新创建一个 binder_thread
  if (*p == NULL) {
    thread = kzalloc(sizeof(*thread), GFP_KERNEL);
    if (thread == NULL)
      return NULL;
    binder_stats_created(BINDER_STAT_THREAD);
    thread->proc = proc;
    thread->pid = current->pid;
    init_waitqueue_head(&thread->wait);
    INIT_LIST_HEAD(&thread->todo);
    rb_link_node(&thread->rb_node, parent, p);
    rb_insert_color(&thread->rb_node, &proc->threads);
    thread->looper |= BINDER_LOOPER_STATE_NEED_RETURN;
    thread->return_error = BR_OK;
    thread->return_error2 = BR_OK;
  }
  return thread;
}
```
在 proc->threads 中根据发起请求线程的 pid 查找 binder_thread 对象，如果没找到，则创建一个，并插入到 proc->threads，然后进行初始化。

##### 1.5.1.2 binder_thread_write
```c
// kernel/drivers/android/binder.c
// buffer = 指向用户空间的 32 位数组，[BC_ENTER_LOOPER, ... ]
// size = 4
// *write_consumed = 0
int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
      void __user *buffer, int size, signed long *consumed)
{
  uint32_t cmd;
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;
  // thread->return_error 默认为 BR_OK
  while (ptr < end && thread->return_error == BR_OK) {
    // 从用户空间取出前 4 个字节为 BC_ENTER_LOOPER
    if (get_user(cmd, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    if (_IOC_NR(cmd) < ARRAY_SIZE(binder_stats.bc)) {
      binder_stats.bc[_IOC_NR(cmd)]++;
      proc->stats.bc[_IOC_NR(cmd)]++;
      thread->stats.bc[_IOC_NR(cmd)]++;
    }
    switch (cmd) {
    case BC_ENTER_LOOPER:
      binder_debug(BINDER_DEBUG_THREADS,
             "binder: %d:%d BC_ENTER_LOOPER\n",
             proc->pid, thread->pid);
      // 如果已经注册了，则写入错误 flag，何用???
      if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) {
        thread->looper |= BINDER_LOOPER_STATE_INVALID;
        binder_user_error("binder: %d:%d ERROR:"
          " BC_ENTER_LOOPER called after "
          "BC_REGISTER_LOOPER\n",
          proc->pid, thread->pid);
      }
      // 标识该 thread 已经就绪
      thread->looper |= BINDER_LOOPER_STATE_ENTERED;
      break;
      ...
    }
    // *consumed = 4
    *consumed = ptr - buffer;
  }
  return 0;
}
```
此步执行完后 bwr.write_consumed 被改为 4。

### 1.5.2 ioctl
```c
// kernel/drivers/android/binder.c
/*
cmd = BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read)
arg = 指向 binder_write_read 结构体，内容如下：
{
  write_size: 4,
  write_consumed: 4,
  write_buffer: 32 个 4 字节的数组，[BC_ENTER_LOOPER, ... ],
  read_size: 32 * 4,
  read_consumed: 0,
  read_buffer: 0
}
*/
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  ...
  switch (cmd) {
  case BINDER_WRITE_READ: {
    struct binder_write_read bwr;
    if (size != sizeof(struct binder_write_read)) {
      ret = -EINVAL;
      goto err;
    }
    // 将用户空间的数据拷贝到内核空间，但是 bwr.write_buffer 目前依然指向用户空间 
    if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    // bwr.write_size 为 4
    if (bwr.write_size > 0) {
      // 由于 write_consumed 和 write_size 都为 4，所以进去后不会执行相关代码
      ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
      ...
    }
    
    // bwr.read_size 为 32*4
    if (bwr.read_size > 0) {
      // 见 1.5.2.1
      ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
      // 如果进程的 todo 里面还有任务要做，那么唤醒工作线程
      if (!list_empty(&proc->todo))
        wake_up_interruptible(&proc->wait);
      if (ret < 0) {
        if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
          ret = -EFAULT;
        goto err;
      }
    }
    
    // 把 bwr 拷贝到用户空间，准备返回到用户空间
    if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    break;
  }
  }
  ret = 0;
err:
  if (thread)
    thread->looper &= ~BINDER_LOOPER_STATE_NEED_RETURN;
  mutex_unlock(&binder_lock);
  ...
  return ret;
}
```
#### 1.5.2.1 binder_thread_read
```c++
// kernel/drivers/android/binder.c
// buffer = 指向用户空间的 4 字节数组，[BC_ENTER_LOOPER, ... ]
// size = 32 * 4
// *consumed = 0
// non_block = 0
static int binder_thread_read(struct binder_proc *proc,
            struct binder_thread *thread,
            void  __user *buffer, int size,
            signed long *consumed, int non_block)
{
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  int ret = 0;
  int wait_for_proc_work;

  if (*consumed == 0) {
    // 由于 consumed 位 0，这里向 buffer 里面写入一个 32 位整数 BR_NOOP
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  // 还没有任务可处理，这里为 true
  wait_for_proc_work = thread->transaction_stack == NULL &&
        list_empty(&thread->todo);
  ...
  // 将当前线程的状态置为等待，稍后如果发现有任务会解除该状态
  thread->looper |= BINDER_LOOPER_STATE_WAITING;
  // 如果当前线程自己没有任务可处理，说明已经准备处理进程的任务，于是这里将 ready_threads 加 1
  if (wait_for_proc_work)
    proc->ready_threads++;
  mutex_unlock(&binder_lock);
  if (wait_for_proc_work) {
    // 只有 binder 线程能到这里来取任务，如果不是则记录异常
    if (!(thread->looper & (BINDER_LOOPER_STATE_REGISTERED |
          BINDER_LOOPER_STATE_ENTERED))) {
      binder_user_error("binder: %d:%d ERROR: Thread waiting "
        "for process work before calling BC_REGISTER_"
        "LOOPER or BC_ENTER_LOOPER (state %x)\n",
        proc->pid, thread->pid, thread->looper);
      wait_event_interruptible(binder_user_error_wait,
             binder_stop_on_user_error < 2);
    }
    binder_set_nice(proc->default_priority);
    if (non_block) {
      // 对于非阻塞情况，如果没有任务则返回
      if (!binder_has_proc_work(proc, thread))
        ret = -EAGAIN;
    } else
      // 对于阻塞情况，则等待唤醒，当 binder_has_proc_work 为 true 时才往后面执行
      // binder_has_proc_work 会检查 proc 的 todo 是否有任务。

      // 目前我们就停在这里等待唤醒。
      ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
  } else {
    // 此时不会走这里。
    // binder_has_thread_work 会检测 thread 的 todo 是否有任务
    if (non_block) {
      if (!binder_has_thread_work(thread))
        ret = -EAGAIN;
    } else
      ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
  }
  // 当线程被唤醒后会获取锁，在释放之前，其他线程即使被唤醒了也阻塞在这里。
  // 只有当获取锁的线程重新进入上面 retry 释放锁后，其他线程方有机会获取锁。
  mutex_lock(&binder_lock);
  // 如果此前线程没有自己的任务，这里准备执行进程任务了，于是可用的线程需要减 1，并
  // 删除线程的等待标识。
  if (wait_for_proc_work)
    proc->ready_threads--;
  thread->looper &= ~BINDER_LOOPER_STATE_WAITING;
  ...
}
```
当在 wait_event_interruptible_exclusive 阻塞等待唤醒时，驱动已经往 read_buffer 里面写入一个整数 BR_NOOP。

# 2 注册 ActivityManagerService

Zygote 进程会创建 SystemServer 进程并调用 SystemServer.main 方法。下面从 main 方法开始看。

## 2.1 addService
```java
// frameworks/base/services/java/com/android/server/SystemServer.java
public static void main(String[] args) {
  new SystemServer().run();
}

private void run() {
  ...
  try {
      startBootstrapServices();
      ...
  } catch (Throwable ex) {
      ...
  }
  ...
}

private void startBootstrapServices() {
  ...
  mActivityManagerService = mSystemServiceManager
    .startService(ActivityManagerService.Lifecycle.class)
    .getService();
  ...
  mActivityManagerService.setSystemProcess();
  ...
}
```
```java
// frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
public void setSystemProcess() {
  try {
    ServiceManager.addService(Context.ACTIVITY_SERVICE, this, true);
    ...
  } catch (PackageManager.NameNotFoundException e) {
    ...
  }
}
```
```java
// frameworks/base/core/java/android/os/ServiceManager.java
// name = "activity"
// service = ActivityManagerService 对象
// allowIsolated = true
public static void addService(String name, IBinder service, boolean allowIsolated) {
  try {
    // addService 见 2.1.2
    getIServiceManager().addService(name, service, allowIsolated);
  } catch (RemoteException e) {
    Log.e(TAG, "error in addService", e);
  }
}

private static IServiceManager getIServiceManager() {
  if (sServiceManager != null) {
    return sServiceManager;
  }

  // Find the service manager
  sServiceManager = ServiceManagerNative.asInterface(BinderInternal.getContextObject());
  return sServiceManager;
}
```
```java
// frameworks/base/core/java/android/os/ServiceManagerNative.java
static final String descriptor = "android.os.IServiceManager";

static public IServiceManager asInterface(IBinder obj) {
  if (obj == null) {
    return null;
  }
  IServiceManager in =
    (IServiceManager)obj.queryLocalInterface(descriptor);
  if (in != null) {
    return in;
  }
  
  return new ServiceManagerProxy(obj);
}
```
BinderInternal.getContextObject() 是一个 native 方法，通过它得到一个 IBinder 对象。这里 obj 是一个 BinderProxy 对象，queryLocalInterface 返回为 null，因此我们得到的是一个 ServiceManagerProxy 对象。

下面看下如果获得 IBinder 对象。

### 2.1.1 BinderInternal.getContextObject
```c++
// android_util_binder.cpp
static jobject android_os_BinderInternal_getContextObject(JNIEnv* env, jobject clazz)
{
   // 见 2.1.1.1
    sp<IBinder> b = ProcessState::self()->getContextObject(NULL);
  // 见 2.1.1.2
    return javaObjectForIBinder(env, b);
}
```

#### 2.1.1.1 ProcessState::self
```c++
// ProcessState.cpp
sp<ProcessState> ProcessState::self()
{
    Mutex::Autolock _l(gProcessMutex);
    if (gProcess != NULL) {
        return gProcess;
    }
    gProcess = new ProcessState;
    return gProcess;
}
```
gProcess 是一个单例，在初始化时会调用 open_driver() 打开 binder 驱动，并将文件符保存至 mDriverFD 字段中。下面看下 getContextObject 的实现。

```c++
// ProcessState.cpp
sp<IBinder> ProcessState::getContextObject(const sp<IBinder>& /*caller*/)
{
  return getStrongProxyForHandle(0);
}

// handle = 0
sp<IBinder> ProcessState::getStrongProxyForHandle(int32_t handle)
{
  sp<IBinder> result;

  AutoMutex _l(mLock);

  // 根据 handle 在一个 vector 中查找，找不到则创建一个 handle_entry
  handle_entry* e = lookupHandleLocked(handle);

  if (e != NULL) {
    // b 为 NULL
    IBinder* b = e->binder;
    if (b == NULL || !e->refs->attemptIncWeak(this)) {
      if (handle == 0) {
        // 检测 context manager 是否已经注册
        Parcel data;
        status_t status = IPCThreadState::self()->transact(
            0, IBinder::PING_TRANSACTION, data, NULL, 0);
        if (status == DEAD_OBJECT)
          return NULL;
      }

      b = new BpBinder(handle); 
      e->binder = b;
      if (b) e->refs = b->getWeakRefs();
      result = b;
    } else {
      // This little bit of nastyness is to allow us to add a primary
      // reference to the remote proxy when this team doesn't have one
      // but another team is sending the handle to us.
      result.force_set(b);
      e->refs->decWeak(this);
    }
  }

  return result;
}
```
getContextObject 返回的是一个构造参数为 0 的 BpBinder 对象。

#### 2.1.1.2 javaObjectForIBinder
```c++
// android_util_Binder.cpp
// val = new BpBinder(0)
jobject javaObjectForIBinder(JNIEnv* env, const sp<IBinder>& val)
{
  if (val == NULL) return NULL;

  // 检测是否为 android.os.Binder 的子类
  if (val->checkSubclass(&gBinderOffsets)) {
    jobject object = static_cast<JavaBBinder*>(val.get())->object();
    return object;
  }

  // For the rest of the function we will hold this lock, to serialize
  // looking/creation of Java proxies for native Binder proxies.
  AutoMutex _l(mProxyLock);

  // Someone else's...  do we know about it?
  // BpBinder 是刚刚创建的 C++对象，不走这里，下一次就会走这里
  jobject object = (jobject)val->findObject(&gBinderProxyOffsets);
  if (object != NULL) {
    ...
  }

  // 创建一个 android.os.BinderProxy 的 Java 对象
  object = env->NewObject(gBinderProxyOffsets.mClass, gBinderProxyOffsets.mConstructor);
  if (object != NULL) {
    LOGDEATH("objectForBinder %p: created new proxy %p !\n", val.get(), object);
    // 将 BpBinder 的地址赋给 BinderProxy 的 mObject 字段
    env->SetLongField(object, gBinderProxyOffsets.mObject, (jlong)val.get());
    val->incStrong((void*)javaObjectForIBinder);

    // The native object needs to hold a weak reference back to the
    // proxy, so we can retrieve the same proxy if it is still active.
    jobject refObject = env->NewGlobalRef(
        env->GetObjectField(object, gBinderProxyOffsets.mSelf));
    val->attachObject(&gBinderProxyOffsets, refObject,
        jnienv_to_javavm(env), proxy_cleanup);

    // Also remember the death recipients registered on this proxy
    sp<DeathRecipientList> drl = new DeathRecipientList;
    drl->incStrong((void*)javaObjectForIBinder);
    env->SetLongField(object, gBinderProxyOffsets.mOrgue, reinterpret_cast<jlong>(drl.get()));

    // Note that a new object reference has been created.
    android_atomic_inc(&gNumProxyRefs);
    incRefsCreated(env);
  }

  // BinderProxy 对象
  return object;
}
```
### 2.1.2 ServiceManagerProxy#addService
```java
// frameworks/base/core/java/android/os/ServiceManagerNative.java
// name = "activity"
// service = ActivityManagerService 对象
// allowIsolated = true
public void addService(String name, IBinder service, boolean allowIsolated)
      throws RemoteException {
  // 见 2.1.3  
  Parcel data = Parcel.obtain();
  Parcel reply = Parcel.obtain();
  // 见 2.1.4
  data.writeInterfaceToken(IServiceManager.descriptor);
  data.writeString(name);
  data.writeStrongBinder(service);
  data.writeInt(allowIsolated ? 1 : 0);
  // 见 2.1.5
  mRemote.transact(ADD_SERVICE_TRANSACTION, data, reply, 0);
  reply.recycle();
  data.recycle();
}
```
这里的 mRemote 便为构造 ServiceManagerProxy 时传入的 BinderProxy 对象，它的 mObject 字段指向一个 BpBinder 的 C++对象，该 BpBinder 对象的 handle 为 0。

往 data 中写入的内容包括：
- 整数：StrictPolicy
- 字符串："android.os.IServiceManager"
- 字符串："activity",
- flat_binder_object 结构体: 
```
{
 flags: 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS,
 type: BINDER_TYPE_BINDER,
 binder: 弱引用,
 cookie: 指向 Binder 对象指针,
}
```
- 整数：1

### 2.1.3 Parcel.obtain
```java
// Parcel.java
public static Parcel obtain() {
  final Parcel[] pool = sOwnedPool;
  synchronized (pool) {
    Parcel p;
    for (int i=0; i<POOL_SIZE; i++) {
      p = pool[i];
      if (p != null) {
        pool[i] = null;
        if (DEBUG_RECYCLE) {
          p.mStack = new RuntimeException();
        }
        return p;
      }
    }
  }
  return new Parcel(0);
}

private Parcel(long nativePtr) {
  init(nativePtr);
}

private void init(long nativePtr) {
  if (nativePtr != 0) {
    mNativePtr = nativePtr;
    mOwnsNativeParcelObject = false;
  } else {
    mNativePtr = nativeCreate();
    mOwnsNativeParcelObject = true;
  }
}
```
obtain() 会先从缓存池中获取 Parcel，如果没有则新创建一个 Parcel 对象，传入参数为 0，接下来调用 native 方法 nativeCreate 来创建一个 native 对象，并将对象指针保存到 mNativePtr 中。

```c++
// android_os_Parcel.cpp
static jlong android_os_Parcel_create(JNIEnv* env, jclass clazz)
{
    Parcel* parcel = new Parcel();
    return reinterpret_cast<jlong>(parcel);
}
```
### 2.1.4 向 Parcel 写入数据
```java
// Parcel.java
// interfaceName = "android.os.IServiceManager"
public final void writeInterfaceToken(String interfaceName) {
  nativeWriteInterfaceToken(mNativePtr, interfaceName);
}
```
调用 native 方法。
```c++
// android_os_Parcel.cpp
// name = "android.os.IServiceManager"
static void android_os_Parcel_writeInterfaceToken(JNIEnv* env, jclass clazz, jlong nativePtr, jstring name){
  Parcel* parcel = reinterpret_cast<Parcel*>(nativePtr);
  if (parcel != NULL) {
    // In the current implementation, the token is just the serialized interface name that
    // the caller expects to be invoking
    const jchar* str = env->GetStringCritical(name, 0);
    if (str != NULL) {
      parcel->writeInterfaceToken(String16(
         reinterpret_cast<const char16_t*>(str),
         env->GetStringLength(name)));
      env->ReleaseStringCritical(name, str);
    }
  }
 }
```
```c++
// Parcel.cpp
// interface = "android.os.IServiceManager"
status_t Parcel::writeInterfaceToken(const String16& interface)
{
  // 写入一个整数标识严格模式 
  writeInt32(IPCThreadState::self()->getStrictModePolicy() |
        STRICT_MODE_PENALTY_GATHER);
  // 写入传入的字符串
  return writeString16(interface);
}
```
写入字符串时首先写入字符串长度，接着写入字符串内容，最后再写入一个整数 0。

data.writeString(name) 和 data.writeInt(allowIsolated ? 1 : 0) 与 writeInterfaceToken 类似，不做分析，下面看看 data.writeStrongBinder：

```c++
// android_os_Parcel.cpp
// object = ActivityManagerService 对象
static void android_os_Parcel_writeStrongBinder(JNIEnv* env, jclass clazz, jlong nativePtr, jobject object)
{
  Parcel* parcel = reinterpret_cast<Parcel*>(nativePtr);
  if (parcel != NULL) {
  // ibinderForJavaObject 见 2.1.4.1
  // writeStrongBinder 见 2.1.4.2
    const status_t err = parcel->writeStrongBinder(ibinderForJavaObject(env, object));
    if (err != NO_ERROR) {
      signalExceptionForError(env, clazz, err);
    }
  }
}
```

#### 2.1.4.1 ibinderForJavaObject
```c++
// android_os_Parcel.cpp
// obj = ActivityManagerService 对象
sp<IBinder> ibinderForJavaObject(JNIEnv* env, jobject obj)
{
  if (obj == NULL) return NULL;

  // 由于 ActivityManagerService 继承 Binder 对象，进入该分支
  if (env->IsInstanceOf(obj, gBinderOffsets.mClass)) {
     // Java 端的 Binder 对象会持有一个 mObject 字段，指向
    // native 端的 JavaBBinderHolder 对象，见 2.1.4.1.1
    JavaBBinderHolder* jbh = (JavaBBinderHolder*)
      env->GetLongField(obj, gBinderOffsets.mObject);
    // jbh->get 返回的是一个 JavaBBinder 对象，见 2.1.4.1.2
    return jbh != NULL ? jbh->get(env, obj) : NULL;
  }

  // 对于非服务类，则继承 BinderProxy，前面已经讲过
  if (env->IsInstanceOf(obj, gBinderProxyOffsets.mClass)) {
    return (IBinder*)
      env->GetLongField(obj, gBinderProxyOffsets.mObject);
  }

  ALOGW("ibinderForJavaObject: %p is not a Binder object", obj);
  return NULL;
}
```
最终返回一个 JavaBBinder 对象，其 mObject 字段引用 ActivityManagerService 对象。

##### 2.1.4.1.1 android_os_Binder_init
ActivityManagerService 继承 Binder 类。Java 端 Binder 类的构造方法会调用一个 native 方法 init，在该 native 方法中会创建一个 JavaBBinderHolder 的 native 对象，并将其地址赋给 Java 对象的 mObject 字段。
```c++
// android_util_Binder.cpp
static void android_os_Binder_init(JNIEnv* env, jobject obj)
{
  JavaBBinderHolder* jbh = new JavaBBinderHolder();
  if (jbh == NULL) {
    jniThrowException(env, "java/lang/OutOfMemoryError", NULL);
    return;
  }
  ALOGV("Java Binder %p: acquiring first ref on holder %p", obj, jbh);
  jbh->incStrong((void*)android_os_Binder_init);
  env->SetLongField(obj, gBinderOffsets.mObject, (jlong)jbh);
}
```
##### 2.1.4.1.2 JavaBBinderHolder#get
```c++ 
// android_util_Binder.cpp#JavaBBinderHolder

wp<JavaBBinder> mBinder;

// obj = ActivityManagerService 对象
sp<JavaBBinder> get(JNIEnv* env, jobject obj)
{
  AutoMutex _l(mLock);
  // mBinder 是一个弱引用，第一次调用返回 NULL
  sp<JavaBBinder> b = mBinder.promote();
  if (b == NULL) {
    b = new JavaBBinder(env, obj);
    mBinder = b;
  }

  return b;
}
```
这里创建一个 JavaBBinder 对象，保存 ActivityManagerService 对象到 mObject 字段中。

#### 2.1.4.2 Parcel#writeStrongBinder
```c++
// Parcel.cpp
// val = JavaBBinder 对象
status_t Parcel::writeStrongBinder(const sp<IBinder>& val)
{
 // 见 2.1.4.2.1
  return flatten_binder(ProcessState::self(), val, this);
}
```
##### 2.1.4.2.1 Parcel#flatten_binder
```c++
// Parcel.cpp
// binder = JavaBBinder 对象
status_t flatten_binder(const sp<ProcessState>& /*proc*/,
    const sp<IBinder>& binder, Parcel* out)
{
  flat_binder_object obj;

  obj.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
  if (binder != NULL) {
    // JavaBBinder 继承 BBinder，所以 localBinder 返回自身
    IBinder *local = binder->localBinder();
    if (!local) {
      BpBinder *proxy = binder->remoteBinder();
      if (proxy == NULL) {
        ALOGE("null proxy");
      }
      const int32_t handle = proxy ? proxy->handle() : 0;
      obj.type = BINDER_TYPE_HANDLE;
      obj.binder = 0; /* Don't pass uninitialized stack data to a remote process */
      obj.handle = handle;
      obj.cookie = 0;
    } else {
      // 走这里   
      obj.type = BINDER_TYPE_BINDER;
      obj.binder = reinterpret_cast<uintptr_t>(local->getWeakRefs());
      obj.cookie = reinterpret_cast<uintptr_t>(local);
    }
  } else {
    obj.type = BINDER_TYPE_BINDER;
    obj.binder = 0;
    obj.cookie = 0;
  }

  return finish_flatten_binder(binder, obj, out);
}

inline static status_t finish_flatten_binder(
    const sp<IBinder>& /*binder*/, const flat_binder_object& flat, Parcel* out)
{
  return out->writeObject(flat, false);
}
```
如果 binder 是 BBinder，那么它标识的服务提供方，obj.cookie 保存的是指向该 binder 的实际指针；如果 binder 是 Bpinder，那么它标识的服务使用方，obj.handle 保存的实际 Binder 在驱动中的一个引用。
```c++
// Parcel.cpp
/*
val = {
 flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS,
 type: BINDER_TYPE_BINDER,
 binder: 弱引用,
 cookie: 指向 Binder 对象指针,
}
nullMetaData = false
*/
status_t Parcel::writeObject(const flat_binder_object& val, bool nullMetaData)
{
  const bool enoughData = (mDataPos+sizeof(val)) <= mDataCapacity;
  const bool enoughObjects = mObjectsSize < mObjectsCapacity;
  if (enoughData && enoughObjects) {
 restart_write:
    *reinterpret_cast<flat_binder_object*>(mData+mDataPos) = val;
    ...
    if (nullMetaData || val.binder != 0) {
      // 记录 flat_binder_object 的在 buffer 中的位置
      mObjects[mObjectsSize] = mDataPos;
      acquire_object(ProcessState::self(), val, this, &mOpenAshmemSize);
      mObjectsSize++;
    }

    return finishWrite(sizeof(flat_binder_object));
  }

  if (!enoughData) {
  ...
  }
  if (!enoughObjects) {
  ...
  }

  goto restart_write;
}
```
如果空间不够则增大空间，并将 val 写入到 Parcel 中，同时记录了 val 在 buffer 中的位置，后面在 binder 驱动中会进行修改。

### 2.1.5 BinderProxy#transact
```java
// Binder.java
// code = IServiceManager.ADD_SERVICE_TRANSACTION
// data = 见 2.1.2 注释
// flags = 0
public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
  Binder.checkParcel(this, code, data, "Unreasonably large binder buffer");
  return transactNative(code, data, reply, flags);
}
```
#### 2.1.5.1 transactNative
```c++
// android_util_Binder.cpp
// code =  IServiceManager.ADD_SERVICE_TRANSACTION
// dataObj = 写入的 Parcel，见 2.1.2 注释
// flags = 0
static jboolean android_os_BinderProxy_transact(JNIEnv* env, jobject obj,
        jint code, jobject dataObj, jobject replyObj, jint flags) // throws RemoteException
{
  if (dataObj == NULL) {
    jniThrowNullPointerException(env, NULL);
    return JNI_FALSE;
  }
  // 从 Java 对象中取出 native 对象
  Parcel* data = parcelForJavaObject(env, dataObj);
  if (data == NULL) {
    return JNI_FALSE;
  }
  Parcel* reply = parcelForJavaObject(env, replyObj);
  if (reply == NULL && replyObj != NULL) {
    return JNI_FALSE;
  }
  
 // mObject = BpBinder(0)
  IBinder* target = (IBinder*)
    env->GetLongField(obj, gBinderProxyOffsets.mObject);
  if (target == NULL) {
    jniThrowException(env, "java/lang/IllegalStateException", "Binder has been finalized!");
    return JNI_FALSE;
  }
  ...
 // 见 2.1.5.2
  status_t err = target->transact(code, *data, reply, flags);
  ...
  if (err == NO_ERROR) {
    return JNI_TRUE;
  } else if (err == UNKNOWN_TRANSACTION) {
    return JNI_FALSE;
  }

  signalExceptionForError(env, obj, err, true /*canThrowRemoteException*/, data->dataSize());
  return JNI_FALSE;
}
```
#### 2.1.5.2 BpBinder#transact
```c++
// BpBinder.cpp
// code =  IServiceManager.ADD_SERVICE_TRANSACTION
// data = 写入的 Parcel，见 2.1.2 注释
// reply = 待写入的 Parcel
// flags = 0
status_t BpBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
  if (mAlive) {
  // 见 2.2
    status_t status = IPCThreadState::self()->transact(
      mHandle, code, data, reply, flags);
    if (status == DEAD_OBJECT) mAlive = 0;
    return status;
  }

  return DEAD_OBJECT;
}
```
IPCThreadState 为每个线程维护了一个实例，通过 IPCThreadState::self() 获取。在 IPCThreadState 初始化时，会将 ProcessState 的进程单例保存到 mProcess 字段中。

## 2.2 IPCThreadState#transact
```c++
// IPCThreadState.cpp
// handle = 0
// code =  IServiceManager.ADD_SERVICE_TRANSACTION
// data = 写入的 Parcel，见 2.1.2 注释
// reply = 待写入的 Parcel
// flags = 0
status_t IPCThreadState::transact(int32_t handle,
                                  uint32_t code, const Parcel& data,
                                  Parcel* reply, uint32_t flags)
{
  flags |= TF_ACCEPT_FDS;
 if (err == NO_ERROR) {
    // 见 2.2.1
    err = writeTransactionData(BC_TRANSACTION, flags, handle, code, data, NULL);
 } 
  ...
 // 不是非阻塞模式，进入该分支
  if ((flags & TF_ONE_WAY) == 0) {
    // reply 不为 NULL
    if (reply) {
      // 见 2.2.2   
      err = waitForResponse(reply);
    } else {
      Parcel fakeReply;
      err = waitForResponse(&fakeReply);
    }
    ...
  } else {
    err = waitForResponse(NULL, NULL);
  }
  
  return err;
}
```
### 2.2.1 writeTransactionData
```c++
// IPCThreadState.cpp
// cmd = BC_TRANSACTION
// binderFlags = TF_ACCEPT_FDS
// handle = 0
// code = IServiceManager.ADD_SERVICE_TRANSACTION
// data = 写入的 Parcel，见 2.1.2 注释
// statusBuffer = null
status_t IPCThreadState::writeTransactionData(int32_t cmd, uint32_t binderFlags,
    int32_t handle, uint32_t code, const Parcel& data, status_t* statusBuffer)
{
  binder_transaction_data tr;

  tr.target.ptr = 0; /* Don't pass uninitialized stack data to a remote process */
  tr.target.handle = handle;
  tr.code = code;
  tr.flags = binderFlags;
  tr.cookie = 0;
  tr.sender_pid = 0;
  tr.sender_euid = 0;
  
  const status_t err = data.errorCheck();
  // 走该分支
  if (err == NO_ERROR) {
    tr.data_size = data.ipcDataSize();
    tr.data.ptr.buffer = data.ipcData();
    // 存储 binder 对象位置的数组字节大小
    tr.offsets_size = data.ipcObjectsCount()*sizeof(binder_size_t);
  // binder 对象的对象位置的数组
    tr.data.ptr.offsets = data.ipcObjects();
  } else if (statusBuffer) {
    tr.flags |= TF_STATUS_CODE;
    *statusBuffer = err;
    tr.data_size = sizeof(status_t);
    tr.data.ptr.buffer = reinterpret_cast<uintptr_t>(statusBuffer);
    tr.offsets_size = 0;
    tr.data.ptr.offsets = 0;
  } else {
    return (mLastError = err);
  }
  // mOut 是发给 binder 驱动的数据  
  mOut.writeInt32(cmd);
  mOut.write(&tr, sizeof(tr));
  
  return NO_ERROR;
 }
```
### 2.2.2 waitForResponse
```c++
// IPCThreadState.cpp
status_t IPCThreadState::waitForResponse(Parcel *reply, status_t *acquireResult)
{
  uint32_t cmd;
  int32_t err;

  while (1) {
  // 见 2.2.3
    if ((err=talkWithDriver()) < NO_ERROR) break;
    if (mIn.dataAvail() == 0) continue;
    cmd = (uint32_t)mIn.readInt32();
    switch (cmd) {
    // 第二个指令 BR_TRANSACTION_COMPLETE  
    case BR_TRANSACTION_COMPLETE:
      if (!reply && !acquireResult) goto finish;
      // 跳出 switch，继续循环
      break;
      ...
    default:
      // 第一个指令 BR_NOOP，executeCommand 不会进行任何操作
      err = executeCommand(cmd);
      if (err != NO_ERROR) goto finish;
      break;
    }
  }
 ...
  return err;
}
```
执行过程为调用 talkWithDriver，向驱动发送数据，然后读取驱动写入的数据，根据 cmd 进行操作。

第一次 talkWithDriver 结束后，mIn 被驱动写入两个整数：BR_NOOP 和 BR_TRANSACTION_COMPLETE。

BR_NOOP 不会执行任何操作，BR_TRANSACTION_COMPLETE 分支执行后继续循环。于是第二次调用 talkWithDriver。

这一次 write_size 为 0，read_size 不为 0。再次发起系统调用见 2.2.8。

### 2.2.3 talkWithDriver
```c++
// IPCThreadState.cpp
// doReceive = true
status_t IPCThreadState::talkWithDriver(bool doReceive)
{
  // mProcess 即为 ProcessState
  if (mProcess->mDriverFD <= 0) {
    return -EBADF;
  }
  
  binder_write_read bwr;
  
  // Is the read buffer empty?
  // 如果为 true 说明驱动写入的数据已经读取完了，或者根本就没数据
  // 当前情况为 true
  const bool needRead = mIn.dataPosition() >= mIn.dataSize();
  
  // outAvail = mOut.dataSize()
  const size_t outAvail = (!doReceive || needRead) ? mOut.dataSize() : 0;
  
  bwr.write_size = outAvail;
  bwr.write_buffer = (uintptr_t)mOut.data();

  // This is what we'll read.
  if (doReceive && needRead) {
    // 初始化 IPCThreadState 时，mIn 和 mOut 容量都为 256
    bwr.read_size = mIn.dataCapacity();
    bwr.read_buffer = (uintptr_t)mIn.data();
  } else {
    bwr.read_size = 0;
    bwr.read_buffer = 0;
  }
  
  // Return immediately if there is nothing to do.
  if ((bwr.write_size == 0) && (bwr.read_size == 0)) return NO_ERROR;

  bwr.write_consumed = 0;
  bwr.read_consumed = 0;
  status_t err;
  do {
    // 系统调用，见 2.2.4
    if (ioctl(mProcess->mDriverFD, BINDER_WRITE_READ, &bwr) >= 0)
      err = NO_ERROR;
    else
      err = -errno;
    ...
  } while (err == -EINTR);

  if (err >= NO_ERROR) {
    if (bwr.write_consumed > 0) {
      if (bwr.write_consumed < mOut.dataSize())
        mOut.remove(0, bwr.write_consumed);
      else
        mOut.setDataSize(0);
    }
    // 8
    if (bwr.read_consumed > 0) {
      // 当读完后，position 就和 size 相同了，发起第二次 talkWithDriver 时 needRead 就为 true
      mIn.setDataSize(bwr.read_consumed);
      mIn.setDataPosition(0);
    }
    return NO_ERROR;
  }
  
  return err;
}
```
发起系统调用，从 2.2.7 系统调用返回后，write_buffer 全部消耗完，read_buffer 中写入两个整数，BR_NOOP 和 BR_TRANSACTION_COMPLETE。接着返回到 2.2.2 waitForResponse。

### 2.2.4 binder_ioctl
```c++
// kernel/drivers/android/binder.c
/*
cmd = BINDER_WRITE_READ
arg = 指向用户空间的 binder_write_read 结构体：
{
  write_size: write_buffer 大小,
  write_consumed: 0,
  write_buffer: [BC_TRANSACTION, binder_transaction_data 对象], // 见 2.2.1
  read_size: 256,
  read_consumed: 0,
  read_buffer: 指向用户空间
}
*/
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret;
  struct binder_proc *proc = filp->private_data;
  struct binder_thread *thread;
  unsigned int size = _IOC_SIZE(cmd);
  void __user *ubuf = (void __user *)arg;
  ...
  mutex_lock(&binder_lock);
  thread = binder_get_thread(proc);
  if (thread == NULL) {
    ret = -ENOMEM;
    goto err;
  }

  switch (cmd) {
  case BINDER_WRITE_READ: {
    struct binder_write_read bwr;
    if (size != sizeof(struct binder_write_read)) {
      ret = -EINVAL;
      goto err;
    }
    if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    // 不为 0，见 2.2.5
    if (bwr.write_size > 0) {
      ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
      if (ret < 0) {
        bwr.read_consumed = 0;
        if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
          ret = -EFAULT;
        goto err;
      }
    }
    // 不为 0，见 2.2.7
    if (bwr.read_size > 0) {
      ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
      if (!list_empty(&proc->todo))
        wake_up_interruptible(&proc->wait);
      if (ret < 0) {
        if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
          ret = -EFAULT;
        goto err;
      }
    }
    binder_debug(BINDER_DEBUG_READ_WRITE,
           "binder: %d:%d wrote %ld of %ld, read return %ld of %ld\n",
           proc->pid, thread->pid, bwr.write_consumed, bwr.write_size,
           bwr.read_consumed, bwr.read_size);
    if (copy_to_user(ubuf, &bwr, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    break;
  }
  }
  ret = 0;
err:
  ...
  return ret;
}

```

### 2.2.5 binder_thread_write
```c++
// kernel/drivers/android/binder.c
// *buffer = [BC_TRANSACTION, binder_transaction_data 对象]// 见 2.2.1
// size = buffer 大小
// *consumed = 0
int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
      void __user *buffer, int size, signed long *consumed)
{
  uint32_t cmd;
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  while (ptr < end && thread->return_error == BR_OK) {
    //取出 cmd 为 BC_TRANSACTION
    if (get_user(cmd, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    ...
    switch (cmd) {
    case BC_TRANSACTION:
    case BC_REPLY: {
      struct binder_transaction_data tr;
      // 从用户空间取出数据，浅拷贝，数据中的指针仍指向用户空间
      if (copy_from_user(&tr, ptr, sizeof(tr)))
        return -EFAULT;
      // ptr 将指向 buffer 的末尾        
      ptr += sizeof(tr);
      // 见 2.2.6      
      binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
      break;
    ...
    }
    }
    // 数据全部消耗，*consumed 等于 buffer 所指向数据的大小
    *consumed = ptr - buffer;
  }
  return 0;
}
```

### 2.2.6 binder_transaction
```c++
// kernel/drivers/android/binder.c
// tr = 指向 binder_transaction_data 对象 // 见 2.2.1
// reply = false
static void binder_transaction(struct binder_proc *proc,
             struct binder_thread *thread,
             struct binder_transaction_data *tr, int reply)
{
  struct binder_transaction *t;
  struct binder_work *tcomplete;
  size_t *offp, *off_end;
  struct binder_proc *target_proc;
  struct binder_thread *target_thread = NULL;
  struct binder_node *target_node = NULL;
  struct list_head *target_list;
  wait_queue_head_t *target_wait;
  struct binder_transaction *in_reply_to = NULL;
  uint32_t return_error;
  ...
  if (reply) {
    ...
  } else {
    // tr->target.handle = 0    
    if (tr->target.handle) {
      ...
    } else {
      // 第 1 阶段已经介绍了
      target_node = binder_context_mgr_node;
      if (target_node == NULL) {
        return_error = BR_DEAD_REPLY;
        goto err_no_context_mgr_node;
      }
    }
    // Service Manager 进程的 proc
    target_proc = target_node->proc;
    if (target_proc == NULL) {
      return_error = BR_DEAD_REPLY;
      goto err_dead_binder;
    }
    if (security_binder_transaction(proc->tsk, target_proc->tsk) < 0) {
      return_error = BR_FAILED_REPLY;
      goto err_invalid_target_handle;
    }
    // tr->flags = TF_ACCEPT_FDS，并不是非阻塞调用
    // thread->transaction_stack = null
    if (!(tr->flags & TF_ONE_WAY) && thread->transaction_stack) {
      ...
    }
  }
  // target_thread = null，没有指定线程，那么后续操作的是目标进程的 todo  
  if (target_thread) {
    target_list = &target_thread->todo;
    target_wait = &target_thread->wait;
  } else {
    target_list = &target_proc->todo;
    target_wait = &target_proc->wait;
  }

  /* TODO: reuse incoming transaction for reply */
  // 为当前的 binder 事务分配内存
  t = kzalloc(sizeof(*t), GFP_KERNEL);
  if (t == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_alloc_t_failed;
  }
  binder_stats_created(BINDER_STAT_TRANSACTION);

  // 为待完成的任务分配内存
  tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);
  if (tcomplete == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_alloc_tcomplete_failed;
  }
  binder_stats_created(BINDER_STAT_TRANSACTION_COMPLETE);

  t->debug_id = ++binder_last_id;

  if (!reply && !(tr->flags & TF_ONE_WAY))
    // 走这里，这里记下发起调用的线程，后面会将数据写入该线程  
    t->from = thread;
  else
    t->from = NULL;
  t->sender_euid = proc->tsk->cred->euid;
  // Service Manager 的 proc
  t->to_proc = target_proc;
  // null
  t->to_thread = target_thread;
  // IServiceManager.ADD_SERVICE_TRANSACTION
  t->code = tr->code;
  // TF_ACCEPT_FDS
  t->flags = tr->flags;
  t->priority = task_nice(current);
  // 分配内存，准备将 tr->data.ptr->buffer 和 tr->data.ptr.offsets
  // 指向的用户数据取出来，见 2.2.6.1
  t->buffer = binder_alloc_buf(target_proc, tr->data_size,
    tr->offsets_size, !reply && (t->flags & TF_ONE_WAY));
  if (t->buffer == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_binder_alloc_buf_failed;
  }
  t->buffer->allow_user_free = 0;
  t->buffer->debug_id = t->debug_id;
  t->buffer->transaction = t;
  t->buffer->target_node = target_node;
  if (target_node)
    // 增加引用计数???  
    binder_inc_node(target_node, 1, 0, NULL);
  // buffer 存储了两部分数据，这里计算存储 offsets 的起始地址
  offp = (size_t *)(t->buffer->data + ALIGN(tr->data_size, sizeof(void *)));
  // 将 buffer 数据取出，具体内容见 2.1.2 注释
  if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) {
    ...
  }
  // 将 buffer 中所包含的 Binder 对象位置信息数组 offsets 取出
  if (copy_from_user(offp, tr->data.ptr.offsets, tr->offsets_size)) {
    ...
  }
  if (!IS_ALIGNED(tr->offsets_size, sizeof(size_t))) {
    binder_user_error("binder: %d:%d got transaction with "
      "invalid offsets size, %zd\n",
      proc->pid, thread->pid, tr->offsets_size);
    return_error = BR_FAILED_REPLY;
    goto err_bad_offset;
  }
  // 指向 offsets 的末尾，也是整个 buffer 的末尾  
  off_end = (void *)offp + tr->offsets_size;
  for (; offp < off_end; offp++) {
    struct flat_binder_object *fp;
    if (*offp > t->buffer->data_size - sizeof(*fp) ||
        t->buffer->data_size < sizeof(*fp) ||
        !IS_ALIGNED(*offp, sizeof(void *))) {
      binder_user_error("binder: %d:%d got transaction with "
        "invalid offset, %zd\n",
        proc->pid, thread->pid, *offp);
      return_error = BR_FAILED_REPLY;
      goto err_bad_offset;
    }
    // 取出 Binder 对象，即起始位置加上一个偏移，这里只有一个对象，内容为：
    // {
    //   flags: 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS,
    //   type: BINDER_TYPE_BINDER,
    //   binder: 弱引用,
    //   cookie: 指向 Binder 对象指针,
    // }
    fp = (struct flat_binder_object *)(t->buffer->data + *offp);
    switch (fp->type) {
    case BINDER_TYPE_BINDER:
    case BINDER_TYPE_WEAK_BINDER: {
      struct binder_ref *ref;
      // 每个进程都在 proc 的 nodes 字段中维护当前进程的 binder_node，binder_node
      // 保存了 Service 的信息，例如地址。驱动会将一个 binder_node 的引用传递给其他
      // 进程。
      struct binder_node *node = binder_get_node(proc, fp->binder);
      if (node == NULL) {
        // 没有查到则新建一个并插入到 proc.nodes 中，这里的 fp->cookie 便是 AMS
        // 在进程中的实际地址。
        node = binder_new_node(proc, fp->binder, fp->cookie);
        if (node == NULL) {
          return_error = BR_FAILED_REPLY;
          goto err_binder_new_node_failed;
        }
        node->min_priority = fp->flags & FLAT_BINDER_FLAG_PRIORITY_MASK;
        node->accept_fds = !!(fp->flags & FLAT_BINDER_FLAG_ACCEPTS_FDS);
      }
      if (fp->cookie != node->cookie) {
        binder_user_error("binder: %d:%d sending u%p "
          "node %d, cookie mismatch %p != %p\n",
          proc->pid, thread->pid,
          fp->binder, node->debug_id,
          fp->cookie, node->cookie);
        goto err_binder_get_ref_for_node_failed;
      }
      ...
      // 为 binder_node 创建一个引用，见 2.2.6.2
      ref = binder_get_ref_for_node(target_proc, node);
      if (ref == NULL) {
        return_error = BR_FAILED_REPLY;
        goto err_binder_get_ref_for_node_failed;
      }
      // 将类型改为 BINDER_TYPE_HANDLE，记住，其他进程持有的都是 handle
      if (fp->type == BINDER_TYPE_BINDER)
        fp->type = BINDER_TYPE_HANDLE;
      else
        fp->type = BINDER_TYPE_WEAK_HANDLE;
      fp->handle = ref->desc;
      binder_inc_ref(ref, fp->type == BINDER_TYPE_HANDLE,
               &thread->todo);
    } break;
  }
  if (reply) {
    ...
  } else if (!(t->flags & TF_ONE_WAY)) {
    BUG_ON(t->buffer->async_transaction != 0);
    // 将事务放在发起调用的线程的事务栈的栈顶    
    t->need_reply = 1;
    t->from_parent = thread->transaction_stack;
    thread->transaction_stack = t;
  } else {
    ...
  }
  t->work.type = BINDER_WORK_TRANSACTION;
  // 将事务的工作添加到目标任务列表中
  list_add_tail(&t->work.entry, target_list);
  // 将标识写完成的工作添加到当前线程的任务列表中
  tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
  list_add_tail(&tcomplete->entry, &thread->todo);
  // 唤醒 Service Manager
  if (target_wait)
    // 见 2.3
    wake_up_interruptible(target_wait);
  return;
  ...// 错误处理
}
```

唤醒目标线程后，继续返回到 2.2.4 binder_ioctl，由于 bwr.read_size 不为 0，进入 2.2.7。ServiceManager 线程在被唤醒后的执行见 2.3。

#### 2.2.6.1 binder_alloc_buf
#### 2.2.6.2 binder_get_ref_for_node

### 2.2.7 binder_thread_read

```c++
if (bwr.read_size > 0) {
  ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
  // 内容为空，此时 thread->todo 不为空
  if (!list_empty(&proc->todo))
    wake_up_interruptible(&proc->wait);
  if (ret < 0) {
    // 将数据读写情况返回给请求方，此时 write buffer 全部读完，
    if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
      ret = -EFAULT;
    goto err;
  }
}

// buffer = 指向内存的大小为 256 字节
// size = 256
// non_block = 0
static int binder_thread_read(struct binder_proc *proc,
            struct binder_thread *thread,
            void  __user *buffer, int size,
            signed long *consumed, int non_block)
{
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  int ret = 0;
  int wait_for_proc_work;

  if (*consumed == 0) {
    // 写入 BR_NOOP
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  // thread->transaction_stack 不为 NULL
  // thread->todo 也不为空
  // wait_for_proc_work = false
  wait_for_proc_work = thread->transaction_stack == NULL &&
        list_empty(&thread->todo);
  ...
  thread->looper |= BINDER_LOOPER_STATE_WAITING;
  if (wait_for_proc_work)
    proc->ready_threads++;
  mutex_unlock(&binder_lock);
  if (wait_for_proc_work) {
    ...
  } else {
    // false
    if (non_block) {
      if (!binder_has_thread_work(thread))
        ret = -EAGAIN;
    } else
      // 走这里，但是当前线程有任务，binder_has_thread_work 执行为 true，继续往下执行
      ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
  }
  mutex_lock(&binder_lock);
  if (wait_for_proc_work)
    proc->ready_threads--;
  thread->looper &= ~BINDER_LOOPER_STATE_WAITING;

  if (ret)
    return ret;

  while (1) {
    uint32_t cmd;
    struct binder_transaction_data tr;
    struct binder_work *w;
    struct binder_transaction *t = NULL;

    if (!list_empty(&thread->todo))
      // 第一次循环走这里，取出任务，类型为 BINDER_WORK_TRANSACTION_COMPLETE
      w = list_first_entry(&thread->todo, struct binder_work, entry);
    else if (!list_empty(&proc->todo) && wait_for_proc_work)
      w = list_first_entry(&proc->todo, struct binder_work, entry);
    else {
      // 第二次循环走这里，由于 thread->looper & BINDER_LOOPER_STATE_NEED_RETURN 为 1，
      // 直接 break。
      // 只有在 ioctl 出错时，thread->looper & BINDER_LOOPER_STATE_NEED_RETURN 才为 0。
      if (ptr - buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
        goto retry;
      break;
    }

    // 一共 256，只写了 4 个字节，还够，往下执行
    if (end - ptr < sizeof(tr) + 4)
      break;

    switch (w->type) {
    case BINDER_WORK_TRANSACTION_COMPLETE: {
      cmd = BR_TRANSACTION_COMPLETE;
      // 写入第二个命令
      if (put_user(cmd, (uint32_t __user *)ptr))
        return -EFAULT;
      ptr += sizeof(uint32_t);

      binder_stat_br(proc, thread, cmd);
      binder_debug(BINDER_DEBUG_TRANSACTION_COMPLETE,
             "binder: %d:%d BR_TRANSACTION_COMPLETE\n",
             proc->pid, thread->pid);
      // 移除任务
      list_del(&w->entry);
      kfree(w);
      binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);
    } break;
    ...
    }

    // t 为 NULL，不往下执行，继续循环
    if (!t)
      continue;
    ...
  }

done:
  // 第二次循环跳出后记下数据写入情况，一共写入两个整数：BR_NOOP 和 BR_TRANSACTION_COMPLETE
  *consumed = ptr - buffer;
  ...
  return 0;
}
```
经过两次循环后，退出 icotl，最终返回到 2.2.3 talkWithDriver，处理数据读写情况：

### 2.2.8 第二次 binder_thread_read
由于第二次 iotcl，write size 为 0，read size 不为 0，于是再次进入 binder_thread_read。

```c++
// buffer = 指向内存的大小为 256 字节
// size = 256
// *consumed = 0
// non_block = 0
static int binder_thread_read(struct binder_proc *proc,
            struct binder_thread *thread,
            void  __user *buffer, int size,
            signed long *consumed, int non_block)
{
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  int ret = 0;
  int wait_for_proc_work;

  if (*consumed == 0) {
    // 写入 BR_NOOP
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  // thread->transaction_stack 不为 NULL
  // thread->todo 为空
  // wait_for_proc_work = false
  wait_for_proc_work = thread->transaction_stack == NULL &&
        list_empty(&thread->todo);
  ...
  thread->looper |= BINDER_LOOPER_STATE_WAITING;
  if (wait_for_proc_work)
    proc->ready_threads++;
  mutex_unlock(&binder_lock);
  if (wait_for_proc_work) {
    ...
  } else {
    // false
    if (non_block) {
      if (!binder_has_thread_work(thread))
        ret = -EAGAIN;
    } else
      // 阻塞在这里，等待 ServiceManager
      ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
  }
 ...
}
```
由于事务栈不为空，且待处理任务为空，于是阻塞，等待 ServiceManager 唤醒。

## 2.3 ServiceManager 唤醒后执行过程
```c++
// buffer = 指向用户空间的 4 字节数组
// size = 32 * 4
// *consumed = 0
// non_block = 0
static int binder_thread_read(struct binder_proc *proc,
            struct binder_thread *thread,
            void  __user *buffer, int size,
            signed long *consumed, int non_block)
{
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  int ret = 0;
  int wait_for_proc_work;

  if (*consumed == 0) {
    // 写入 BR_NOOP
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  wait_for_proc_work = thread->transaction_stack == NULL &&
        list_empty(&thread->todo);
  ...
  thread->looper |= BINDER_LOOPER_STATE_WAITING;
  if (wait_for_proc_work)
    proc->ready_threads++;
  mutex_unlock(&binder_lock);
  if (wait_for_proc_work) {
    ...
    if (non_block) {
      ...
    } else
      // 从这里唤醒，binder_has_proc_work 返回为 true，继续往下执行
      ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
  } else {
    ...
  }
  mutex_lock(&binder_lock);
  if (wait_for_proc_work)
    // 可用线程减 1
    proc->ready_threads--;
  thread->looper &= ~BINDER_LOOPER_STATE_WAITING;

  if (ret)
    return ret;

  while (1) {
    uint32_t cmd;
    struct binder_transaction_data tr;
    struct binder_work *w;
    struct binder_transaction *t = NULL;
    // thread->todo 为空
    if (!list_empty(&thread->todo))
      w = list_first_entry(&thread->todo, struct binder_work, entry);
    else if (!list_empty(&proc->todo) && wait_for_proc_work)
      // 取出 2.2.6 中添加的 work，type 为 BINDER_WORK_TRANSACTION
      w = list_first_entry(&proc->todo, struct binder_work, entry);
    else {
      ...
    }

    if (end - ptr < sizeof(tr) + 4)
      break;

    switch (w->type) {
    case BINDER_WORK_TRANSACTION: {
      t = container_of(w, struct binder_transaction, work);
    } break;
    ...
    }

    if (!t)
      continue;
    
    if (t->buffer->target_node) {
      struct binder_node *target_node = t->buffer->target_node;
      tr.target.ptr = target_node->ptr;
      tr.cookie =  target_node->cookie; //Service Manger 的实际地址
      t->saved_priority = task_nice(current);
      if (t->priority < target_node->min_priority &&
          !(t->flags & TF_ONE_WAY))
        binder_set_nice(t->priority);
      else if (!(t->flags & TF_ONE_WAY) ||
         t->saved_priority > target_node->min_priority)
        binder_set_nice(target_node->min_priority);
      // 设置 cmd 为 BR_TRANSACTION
      cmd = BR_TRANSACTION;
    } else {
      tr.target.ptr = NULL;
      tr.cookie = NULL;
      cmd = BR_REPLY;
    }
    // IServiceManager.ADD_SERVICE_TRANSACTION 
    tr.code = t->code;
    // TF_ACCEPT_FDS
    tr.flags = t->flags;
    tr.sender_euid = t->sender_euid;

    if (t->from) {
      struct task_struct *sender = t->from->proc->tsk;
      tr.sender_pid = task_tgid_nr_ns(sender,
              current->nsproxy->pid_ns);
    } else {
      tr.sender_pid = 0;
    }

    tr.data_size = t->buffer->data_size;
    tr.offsets_size = t->buffer->offsets_size;
    // 将内核地址转为进程地址，这次无需拷贝
    tr.data.ptr.buffer = (void *)t->buffer->data +
          proc->user_buffer_offset;
    tr.data.ptr.offsets = tr.data.ptr.buffer +
          ALIGN(t->buffer->data_size,
              sizeof(void *));

    // 将 BR_TRANSACTION 写入读 buffer
    if (put_user(cmd, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    // 将事务相关的信息写入读 buffer
    if (copy_to_user(ptr, &tr, sizeof(tr)))
      return -EFAULT;
    ptr += sizeof(tr);

    ...

    // 任务已处理，删除工作任务
    list_del(&t->work.entry);
    // ServiceManager 处理完成后会通知驱动释放内存
    t->buffer->allow_user_free = 1;
    if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) {
      // 把事务放置栈顶，稍后要据此反馈客户
      t->to_parent = thread->transaction_stack;
      t->to_thread = thread;
      thread->transaction_stack = t;
    } else {
      t->buffer->transaction = NULL;
      kfree(t);
      binder_stats_deleted(BINDER_STAT_TRANSACTION);
    }
    break;
  }

done:

  *consumed = ptr - buffer;
  ...
  return 0;
}
```
写入的读 buffer 数据包括 [BR_NOOP, BR_TRANSACTION, binder_transaction_data]。

接着返回到 1.3 binder_loop 中开始执行 binder_parse，见 2.3.1。

### 2.3.1 binder_parse
```c++
// frameworks/native/cmds/servicemanager/binder.c
// bs = binder_open 的返回值
// ptr = 指向的数据包含 [BR_NOOP, BR_TRANSACTION, binder_transaction_data]
// size = ptr 指向数据的大小
// func = svcmgr_handler
int binder_parse(struct binder_state *bs, struct binder_io *bio,
                 uintptr_t ptr, size_t size, binder_handler func)
{
    int r = 1;
    uintptr_t end = ptr + (uintptr_t) size;

    while (ptr < end) {
        uint32_t cmd = *(uint32_t *) ptr;
        ptr += sizeof(uint32_t);
        switch(cmd) {
        case BR_NOOP:
            break;
        case BR_TRANSACTION: {
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: txn too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (func) {
                unsigned rdata[256/4];
                struct binder_io msg;
                struct binder_io reply;
                int res;
                // 见 2.3.1.1
                bio_init(&reply, rdata, sizeof(rdata), 4);
                // 见 2.3.1.2
                bio_init_from_txn(&msg, txn);
                // 见 2.3.1.3
                res = func(bs, txn, &msg, &reply);
                // 见 2.3.1.4
                binder_send_reply(bs, &reply, txn->data.ptr.buffer, res);
            }
            ptr += sizeof(*txn);
            break;
        }
        ...
        }
    }

    return r;
}
```
binder_io 定义如下：
```c++
struct binder_io
{
  char *data;            /* pointer to read/write from */
  binder_size_t *offs;   /* array of offsets */
  size_t data_avail;     /* bytes available in data buffer */
  size_t offs_avail;     /* entries available in offsets array */

  char *data0;           /* start of data buffer */
  binder_size_t *offs0;  /* start of offsets buffer */
  uint32_t flags;
  uint32_t unused;
};
```
#### 2.3.1.1 bio_init
```c++
// bio = 指向 binder_io 结构体实例
// data = 数组
// maxdata = 256
// maxoffs = 4 最多有多少个 binder 对象
void bio_init(struct binder_io *bio, void *data,
              size_t maxdata, size_t maxoffs)
{
    // 对象偏移位置为 4 字节整数
    size_t n = maxoffs * sizeof(size_t);

    // 给的空间太小
    if (n > maxdata) {
        bio->flags = BIO_F_OVERFLOW;
        bio->data_avail = 0;
        bio->offs_avail = 0;
        return;
    }
    
    // 整段 buffer 前面存储 binder 对象偏移位置信息，后面存储其他数据
    bio->data = bio->data0 = (char *) data + n;
    bio->offs = bio->offs0 = data;
    bio->data_avail = maxdata - n;
    bio->offs_avail = maxoffs;
    bio->flags = 0;
}
```

#### 2.3.1.2 bio_init_from_txn
```c++
// bio = 指向 binder_io 结构体实例
void bio_init_from_txn(struct binder_io *bio, struct binder_transaction_data *txn)
{
    bio->data = bio->data0 = (char *)(intptr_t)txn->data.ptr.buffer;
    bio->offs = bio->offs0 = (binder_size_t *)(intptr_t)txn->data.ptr.offsets;
    bio->data_avail = txn->data_size;
    bio->offs_avail = txn->offsets_size / sizeof(size_t);
    bio->flags = BIO_F_SHARED;
}
```

#### 2.3.1.3 svcmgr_handler
```c++
// service_manager.c
int svcmgr_handler(struct binder_state *bs,
                   struct binder_transaction_data *txn,
                   struct binder_io *msg,
                   struct binder_io *reply)
{
    struct svcinfo *si;
    uint16_t *s;
    size_t len;
    uint32_t handle;
    uint32_t strict_policy;
    int allow_isolated;

    // 都为 0
    if (txn->target.ptr != BINDER_SERVICE_MANAGER)
        return -1;
    // txn->code = IServiceManager.ADD_SERVICE_TRANSACTION
    if (txn->code == PING_TRANSACTION)
        return 0;

    // Equivalent to Parcel::enforceInterface(), reading the RPC
    // header with the strict mode policy mask and the interface name.
    // Note that we ignore the strict_policy and don't propagate it
    // further (since we do no outbound RPCs anyway).
    strict_policy = bio_get_uint32(msg);
    // s = "android.os.IServiceManager"
    s = bio_get_string16(msg, &len);
    if (s == NULL) {
        return -1;
    }

    if ((len != (sizeof(svcmgr_id) / 2)) ||
        memcmp(svcmgr_id, s, sizeof(svcmgr_id))) {
        fprintf(stderr,"invalid id %s\n", str8(s, len));
        return -1;
    }
    ...
    switch(txn->code) {
    ...
    case SVC_MGR_ADD_SERVICE:
        // s = "activity"
        s = bio_get_string16(msg, &len);
        if (s == NULL) {
            return -1;
        }
        // msg 中找到 flat_binder_object，取出其中的 handle 字段
        handle = bio_get_ref(msg);
        // allow_isolated = 1
        allow_isolated = bio_get_uint32(msg) ? 1 : 0;
        // 将服务加入到 service manager 中，以 s 作为索引插入到链表中
        if (do_add_service(bs, s, len, handle, txn->sender_euid,
            allow_isolated, txn->sender_pid))
            return -1;
        break;
    }

    // 将 0 写入到 reply 中
    bio_put_uint32(reply, 0);
    return 0;
}

```
#### 2.3.1.4 binder_send_reply
```c++
// frameworks/native/cmds/servicemanager/binder.c
// reply = 包含一个写入的整数 0
// buffer_to_free = 驱动为这次事务分配的 buffer
// status = 0
void binder_send_reply(struct binder_state *bs,
                       struct binder_io *reply,
                       binder_uintptr_t buffer_to_free,
                       int status)
{
    struct {
        uint32_t cmd_free;
        binder_uintptr_t buffer;
        uint32_t cmd_reply;
        struct binder_transaction_data txn;
    } __attribute__((packed)) data;

    data.cmd_free = BC_FREE_BUFFER;
    data.buffer = buffer_to_free;
    data.cmd_reply = BC_REPLY;
    data.txn.target.ptr = 0;
    data.txn.cookie = 0;
    data.txn.code = 0;
    if (status) {
        ...
    } else {
        data.txn.flags = 0;
        data.txn.data_size = reply->data - reply->data0;
        data.txn.offsets_size = ((char*) reply->offs) - ((char*) reply->offs0);
        data.txn.data.ptr.buffer = (uintptr_t)reply->data0;
        data.txn.data.ptr.offsets = (uintptr_t)reply->offs0;
    }
    binder_write(bs, &data, sizeof(data));
}

// data = [BC_FREE_BUFFER, buffer_to_free, BC_REPLY, binder_transaction_data]
// len = data 的大小
int binder_write(struct binder_state *bs, void *data, size_t len)
{
    struct binder_write_read bwr;
    int res;

    bwr.write_size = len;
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) data;
    bwr.read_size = 0;
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    // 重新发起系统调用，见 2.4
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}
```
## 2.4 Service Manager 反馈
Service Manager 处理完成后，重新调用 ioctl，一是释放内存，而是反馈结果。read_size 为 0，write_size 不为 0，直接进入 binder_thread_write。
```c++
// kernel/drivers/android/binder.c
// buffer = [BC_FREE_BUFFER, buffer_to_free, BC_REPLY, binder_transaction_data]
// size = buffer size
// *consumed = 0
int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
      void __user *buffer, int size, signed long *consumed)
{
  uint32_t cmd;
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  while (ptr < end && thread->return_error == BR_OK) {
    if (get_user(cmd, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    ...
    switch (cmd) {
    ...
    // 第一指令便是 BC_FREE_BUFFER
    case BC_FREE_BUFFER: {
      void __user *data_ptr;
      struct binder_buffer *buffer;
      if (get_user(data_ptr, (void * __user *)ptr))
        return -EFAULT;
      ptr += sizeof(void *);
      // 见 2.4.1 
      buffer = binder_buffer_lookup(proc, data_ptr);
      if (buffer == NULL) {
        binder_user_error("binder: %d:%d "
          "BC_FREE_BUFFER u%p no match\n",
          proc->pid, thread->pid, data_ptr);
        break;
      }
      // ServiceManager 唤醒后将其置为 1
      if (!buffer->allow_user_free) {
        binder_user_error("binder: %d:%d "
          "BC_FREE_BUFFER u%p matched "
          "unreturned buffer\n",
          proc->pid, thread->pid, data_ptr);
        break;
      }

      if (buffer->transaction) {
        buffer->transaction->buffer = NULL;
        buffer->transaction = NULL;
      }
      if (buffer->async_transaction && buffer->target_node) {
        ...
      }
      // 见 2.4.2
      binder_transaction_buffer_release(proc, buffer, NULL);
      // 见 2.4.3
      binder_free_buf(proc, buffer);
      break;
    }

    case BC_TRANSACTION:
    // 第二个指令是 BC_REPLY
    case BC_REPLY: {
      struct binder_transaction_data tr;
      if (copy_from_user(&tr, ptr, sizeof(tr)))
        return -EFAULT;
      ptr += sizeof(tr);
      // 见 2.4.4
      binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
      break;
    }
    ...
    *consumed = ptr - buffer;
  }
  return 0;
}
```
### 2.4.4 binder_transaction
```c++
// kernel/drivers/android/binder.c
// thread = ServiceManager 所在的 thread
// reply = 1
static void binder_transaction(struct binder_proc *proc,
             struct binder_thread *thread,
             struct binder_transaction_data *tr, int reply)
{
  struct binder_transaction *t;
  struct binder_work *tcomplete;
  size_t *offp, *off_end;
  struct binder_proc *target_proc;
  struct binder_thread *target_thread = NULL;
  struct binder_node *target_node = NULL;
  struct list_head *target_list;
  wait_queue_head_t *target_wait;
  struct binder_transaction *in_reply_to = NULL;
  uint32_t return_error;

  if (reply) {
    in_reply_to = thread->transaction_stack;
    if (in_reply_to == NULL) {
      ... // error stuff
      goto err_empty_call_stack;
    }
    binder_set_nice(in_reply_to->saved_priority);
    if (in_reply_to->to_thread != thread) {
      ... // error stuff
      goto err_bad_call_stack;
    }
    // 恢复线程之前的事务栈
    thread->transaction_stack = in_reply_to->to_parent;
    // 发起添加服务请求的线程
    target_thread = in_reply_to->from;
    if (target_thread == NULL) {
      return_error = BR_DEAD_REPLY;
      goto err_dead_binder;
    }
    if (target_thread->transaction_stack != in_reply_to) {
      ... // error stuff
      goto err_dead_binder;
    }
    // 发起添加服务请求所在进程的 proc
    target_proc = target_thread->proc;
  } else {
    ...
  }
  if (target_thread) {
    target_list = &target_thread->todo;
    target_wait = &target_thread->wait;
  } else {
    ...
  }

  t = kzalloc(sizeof(*t), GFP_KERNEL);
  if (t == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_alloc_t_failed;
  }
  binder_stats_created(BINDER_STAT_TRANSACTION);

  tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);
  if (tcomplete == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_alloc_tcomplete_failed;
  }
  binder_stats_created(BINDER_STAT_TRANSACTION_COMPLETE);

  t->debug_id = ++binder_last_id;
  ...
  if (!reply && !(tr->flags & TF_ONE_WAY))
    t->from = thread;
  else
    // 走这里
    t->from = NULL;
  t->sender_euid = proc->tsk->cred->euid;
  t->to_proc = target_proc;
  t->to_thread = target_thread;
  t->code = tr->code;
  t->flags = tr->flags;
  t->priority = task_nice(current);
  // tr->data_size = 1
  // tr->offsets_size = 0
  t->buffer = binder_alloc_buf(target_proc, tr->data_size,
    tr->offsets_size, !reply && (t->flags & TF_ONE_WAY));
  if (t->buffer == NULL) {
    return_error = BR_FAILED_REPLY;
    goto err_binder_alloc_buf_failed;
  }
  t->buffer->allow_user_free = 0;
  t->buffer->debug_id = t->debug_id;
  t->buffer->transaction = t;
  t->buffer->target_node = target_node;
  if (target_node)
    binder_inc_node(target_node, 1, 0, NULL);

  offp = (size_t *)(t->buffer->data + ALIGN(tr->data_size, sizeof(void *)));
  // 从用户空间将数据拷出来，只有一个整数 0
  if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) {
    binder_user_error("binder: %d:%d got transaction with invalid "
      "data ptr\n", proc->pid, thread->pid);
    return_error = BR_FAILED_REPLY;
    goto err_copy_data_failed;
  }
  // 没有 offsets
  if (copy_from_user(offp, tr->data.ptr.offsets, tr->offsets_size)) {
    binder_user_error("binder: %d:%d got transaction with invalid "
      "offsets ptr\n", proc->pid, thread->pid);
    return_error = BR_FAILED_REPLY;
    goto err_copy_data_failed;
  }
  ...
  off_end = (void *)offp + tr->offsets_size;
  for (; offp < off_end; offp++) {
    ...
  }
  if (reply) {
    BUG_ON(t->buffer->async_transaction != 0);
    // 见 2.4.4.1
    binder_pop_transaction(target_thread, in_reply_to);
  } else if (!(t->flags & TF_ONE_WAY)) {
    ...
  } else {
    ...
  }
  t->work.type = BINDER_WORK_TRANSACTION;
  list_add_tail(&t->work.entry, target_list);
  tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
  list_add_tail(&tcomplete->entry, &thread->todo);
  if (target_wait)
    // 唤醒目标线程，即发起添加服务请求的线程
    wake_up_interruptible(target_wait);
  return;
... // 错误处理
}
```
由于这次系统调用的 read_size 为 0，ServiceManager 处里完成后，直接返回 1.5 binder_loop 中进行下一次循环，重新发起系统调用，这一次 write_size 为 0，但 read_size 不为 0，于是重新进入 binder_thread_read。此时，thread->transaction_stack 为空，thread->todo 有一个类型为 BINDER_WORK_TRANSACTION_COMPLETE 的任务，于是向 read_buffer 中写入 BR_NOOP 和 BR_TRANSACTION_COMPLETE。binder_parse 不会对这两个指令做处理，于是又进入下一轮循环，再发起系统调用，write_size 为 0，read_size 不为 0，进入 binder_thread_read，这一次，thread->transaction_stack 和 thread->todo 都为空，于是就阻塞了，等待唤醒。

接下来看下目标线程被唤醒后的执行情况，见 2.5。

#### 2.4.4.1 binder_pop_transaction
```c++
// kernel/drivers/android/binder.c
static void binder_pop_transaction(struct binder_thread *target_thread,
           struct binder_transaction *t)
{
  if (target_thread) {
    BUG_ON(target_thread->transaction_stack != t);
    BUG_ON(target_thread->transaction_stack->from != target_thread);
    target_thread->transaction_stack =
      target_thread->transaction_stack->from_parent;
    t->from = NULL;
  }
  t->need_reply = 0;
  if (t->buffer)
    t->buffer->transaction = NULL;
  kfree(t);
  binder_stats_deleted(BINDER_STAT_TRANSACTION);
}
```
还原发起添加服务请求线程的事务栈。

## 2.5 添加服务返回
添加服务的线程在 2.2.8 中阻塞，在被 ServiceManager 唤醒后将继续往下执行。此时，线程事务栈被清空，线程 todo 列表中有一个类型为 BINDER_WORK_TRANSACTION 的任务。
```c++
// kernel/drivers/android/binder.c
static int binder_thread_read(struct binder_proc *proc,
            struct binder_thread *thread,
            void  __user *buffer, int size,
            signed long *consumed, int non_block)
{
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  int ret = 0;
  int wait_for_proc_work;

  if (*consumed == 0) {
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  wait_for_proc_work = thread->transaction_stack == NULL &&
        list_empty(&thread->todo);

  thread->looper |= BINDER_LOOPER_STATE_WAITING;
  if (wait_for_proc_work)
    ...
  } else {
    if (non_block) {
      ...
    } else
      // 从这里被唤醒
      ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
  }
  mutex_lock(&binder_lock);
  ...
  if (ret)
    return ret;

  while (1) {
    uint32_t cmd;
    struct binder_transaction_data tr;
    struct binder_work *w;
    struct binder_transaction *t = NULL;

    if (!list_empty(&thread->todo))
      w = list_first_entry(&thread->todo, struct binder_work, entry);
    else if (!list_empty(&proc->todo) && wait_for_proc_work)
      ...
    else {
      ...
    }

    if (end - ptr < sizeof(tr) + 4)
      break;

    switch (w->type) {
    case BINDER_WORK_TRANSACTION: {
      t = container_of(w, struct binder_transaction, work);
    } break;
    ...
    }

    if (!t)
      continue;
    // t->buffer->target_node = null
    if (t->buffer->target_node) {
      ...
    } else {
      tr.target.ptr = NULL;
      tr.cookie = NULL;
      cmd = BR_REPLY;
    }
    // 
    tr.code = t->code;
    tr.flags = t->flags;
    tr.sender_euid = t->sender_euid;
    
    // t->from = NULL
    if (t->from) {
      ...
    } else {
      tr.sender_pid = 0;
    }
    
    // data_size = 1，只有一个 0
    tr.data_size = t->buffer->data_size;
    // offsets_size = 0
    tr.offsets_size = t->buffer->offsets_size;
    tr.data.ptr.buffer = (void *)t->buffer->data +
          proc->user_buffer_offset;
    tr.data.ptr.offsets = tr.data.ptr.buffer +
          ALIGN(t->buffer->data_size,
              sizeof(void *));
    // BR_REPLY
    if (put_user(cmd, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
    if (copy_to_user(ptr, &tr, sizeof(tr)))
      return -EFAULT;
    ptr += sizeof(tr);
    ...
    list_del(&t->work.entry);
    t->buffer->allow_user_free = 1;
    if (cmd == BR_TRANSACTION && !(t->flags & TF_ONE_WAY)) {
      ...
    } else {
      t->buffer->transaction = NULL;
      kfree(t);
      binder_stats_deleted(BINDER_STAT_TRANSACTION);
    }
    break;
  }

done:
  *consumed = ptr - buffer;
  ...
  return 0;
}
```
执行完后，写入 read_buffer 两个指令 BR_NOOP 和 BR_REPLY，然后返回到 waitForResponse 中，见 2.5.1

### 2.5.1 waitForResponse
```c++
// IPCThreadState.cpp
status_t IPCThreadState::waitForResponse(Parcel *reply, status_t *acquireResult)
{
  uint32_t cmd;
  int32_t err;

  while (1) {
    if ((err=talkWithDriver()) < NO_ERROR) break;
    if (mIn.dataAvail() == 0) continue;
    cmd = (uint32_t)mIn.readInt32();
    switch (cmd) {
      case BR_REPLY:
      {
        binder_transaction_data tr;
        err = mIn.read(&tr, sizeof(tr));
        ALOG_ASSERT(err == NO_ERROR, "Not enough command data for brREPLY");
        if (err != NO_ERROR) goto finish;

        if (reply) {
          if ((tr.flags & TF_STATUS_CODE) == 0) {
            // 将返回的数据 0 写入到 reply 中，进入 finish
            reply->ipcSetDataReference(
                reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                tr.data_size,
                reinterpret_cast<const binder_size_t*>(tr.data.ptr.offsets),
                tr.offsets_size/sizeof(binder_size_t),
                freeBuffer, this);
          } else {
            ...
          }
        } else {
          ...
        }
      }
      goto finish;
    default:
      // 第一个指令 BR_NOOP，executeCommand 不会进行任何操作
      err = executeCommand(cmd);
      if (err != NO_ERROR) goto finish;
      break;
    }
  }
 ...
  return err;
}
```
将返回的数据 0 写入到 reply 中，进入 finish，然后层层返回，添加 Service 流程执行结束。

我们知道，Service Manger 在处理完任务反馈时，先执行了一个指令 BC_FREE_BUFFER 来释放分配的内存，由于这里是直接返回，不再进行系统调用，那么问题来了，Service Manager 反馈时内核分配的内存该如何清理呢？

在调用 ipcSetDataReference 时，同时传入了一个清理方法 freeBuffer，该方法最终会在 Java 端调用 Parcel.recycle() 时执行，下面看看它的实现：
```c++
void IPCThreadState::freeBuffer(Parcel* parcel, const uint8_t* data,
                                size_t /*dataSize*/,
                                const binder_size_t* /*objects*/,
                                size_t /*objectsSize*/, void* /*cookie*/)
{
    ALOG_ASSERT(data != NULL, "Called with NULL data");
    if (parcel != NULL) parcel->closeFileDescriptors();
    IPCThreadState* state = self();
    state->mOut.writeInt32(BC_FREE_BUFFER);
    state->mOut.writePointer((uintptr_t)data);
}
```
这里往 mOut 中添加了一个 BC_FREE_BUFFER 指令，只能等待下一次该线程发起 iotcl 时通知驱动来清理了。

## 2.6 总结

### 2.6.1 调用流程

调用方发起 BC_TRANSACTION，将事务放到线程事务栈栈顶，并在线程 todo 中添加一个类型为 BINDER_WORK_TRANSACTION_COMPLETE 的任务，同时在目标线程（没有指定线程，便唤醒 proc->wait，也即主线程）todo 中添加一个类型为 BINDER_WORK_TRANSACTION 的任务，并唤醒目标线程。调用方然后开始 read 流程，处理并清除线程中的 todo 任务（BINDER_WORK_TRANSACTION_COMPLETE），返回命令 BR_TRANSACTION_COMPLETE，然后重新进入 read，阻塞，等待唤醒。

目标线程被唤醒后，处理并清除 todo 中的任务（BINDER_WORK_TRANSACTION），返回命令 BR_TRANSACTION。处理完成调用方指定的工作后，反馈命令 BC_FREE_BUFFER 和 BC_REPLY，前者用来释放上一阶段驱动分配的内存，后者开始反馈，往线程 todo 中添加一个类型为 BINDER_WORK_TRANSACTION_COMPLETE 的任务，同时清理调用方线程栈顶的事务，并往调用方线程 todo 中添加一个类型为 BINDER_WORK_TRANSACTION 的任务，然后唤醒调用方线程。目标线程接着开始 read 流程，处理并清除线程中的 todo 任务（BINDER_WORK_TRANSACTION_COMPLETE），返回命令 BR_TRANSACTION_COMPLETE，然后重新进入 read，阻塞，等待再次被唤醒。

调用方线程被唤醒后，处理并清除 todo 中的任务（BINDER_WORK_TRANSACTION），返回命令 BR_REPLY，接着一路返回。

### 2.6.2 关于 Binder

在 Java 中，IBinder 是基础接口，Binder 和 BinderProxy 都继承 IBinder。服务提供着需要继承 Binder，例如 ActivityManagerService。而服务调用者则包含一个 BinderProxy 对象，例如 ActivityManagerProxy。服务提供者和服务调用者都需要实现业务接口，二者皆实现 IActivityManager。简化的代码如下：
```java
interface IInterface {
  public IBinder asBinder();
}
interface IBinder {
  public boolean transact();
  public IInterface queryLocalInterface(String descriptor)
}
class BinderProxy implements IBinder {
  public boolean transact() {
    // 最终发起 binder 系统调用
  }
  public IInterface queryLocalInterface(String descriptor) {
    return null;
  }
}
class Binder implements IBinder {
  private IInterface mOwner;
  private String mDescriptor;

  protected boolean onTransact() {}
  public final boolean transact() {
    boolean r = onTransact(code, data, reply, flags);
    return r;
  }
  public void attachInterface(IInterface owner, String descriptor) {
    mOwner = owner;
    mDescriptor = descriptor;
  }
  public IInterface queryLocalInterface(String descriptor) {
    if (mDescriptor.equals(descriptor)) {
      return mOwner;
    }
    return null;
  }
}
interface IActivityManager implements IInterface {
  void startActivity()
}
class ActivityManagerProxy implements IActivityManager {
  IBinder mRemote;
  ActivityManagerProxy(IBinder remote) {
    this.mRemote = remote;
  }
  void startActivity() {
    mRemote.transact("startActivity")
  }
  public IBinder asBinder() {
    return mRemote;
  }
}
class ActivityManagerService implements IActivityManager, Binder {
  public ActivityManagerNative() {
    attachInterface(this, "android.app.IActivityManager");
  }
  public IBinder asBinder() {
    return this;
  }
  void startActivity() {
    // 最终实现的功能
  }
  protected boolean onTransact() {
    switch(xx) {
      case "startActivity":
        startActivity();
        break;
    }
  }
}
```
调用流程：
```
ActivityManagerProxy.startActivity
mRemote.transact()
Binder Driver
ActivityManagerService.onTransact
ActivityManagerService.startActivity
```
将 IBinder 转为业务类型：
```java
static public IActivityManager asInterface(IBinder obj) {
  if (obj == null) {
      return null;
  }
  IActivityManager in =
      (IActivityManager)obj.queryLocalInterface("android.app.IActivityManager");
  if (in != null) {
    return in;
  }

  return new ActivityManagerProxy(obj);
}
```

# 3 startActivity 流程
这里只分析与 Binder 调用相关的流程，分析到 AcitivityManagerService 就可以了，忽略其他细节。

通常调用 startActivity 最终会调用 Instrumentation#execStartActivity，就从这里开始看。

## 3.1 Instrumentation#execStartActivity
```java
// Instrumentation.java
public ActivityResult execStartActivity(
    Context who, IBinder contextThread, IBinder token, String target,
    Intent intent, int requestCode, Bundle options) {
    IApplicationThread whoThread = (IApplicationThread) contextThread;
    ...
    try {
        intent.migrateExtraStreamToClipData();
        intent.prepareToLeaveProcess();
        // 见 3.1.1
        int result = ActivityManagerNative.getDefault()
            .startActivity(whoThread, who.getBasePackageName(), intent,
                    intent.resolveTypeIfNeeded(who.getContentResolver()),
                    token, target, requestCode, 0, null, options);
        checkStartActivityResult(result, intent);
    } catch (RemoteException e) {
        throw new RuntimeException("Failure from system", e);
    }
    return null;
}
```

## 3.2 获得 ActivityManager 服务
```java
// ActivityManagerNative.java
static public IActivityManager getDefault() {
    // 单例模式，第一次调用会指向下面的 gDefault.create 方法
    return gDefault.get();
}

private static final Singleton<IActivityManager> gDefault = new Singleton<IActivityManager>() {
    protected IActivityManager create() {
        // 见 3.2.1
        IBinder b = ServiceManager.getService("activity");
        if (false) {
            Log.v("ActivityManager", "default service binder = " + b);
        }
        // 见 3.2.4
        IActivityManager am = asInterface(b);
        if (false) {
            Log.v("ActivityManager", "default service = " + am);
        }
        return am;
    }
};
```

最终返回的是 ActivityManagerProxy，传入的构造参数为 BinderProxy，其 mObject 字段指向 native 对象 BpBinder，其 handle 最终指向 ActivityManagerService。

### 3.2.1 ServiceManager#getService
```java
// ServiceManager.java
// name = "activity"
public static IBinder getService(String name) {
    try {
        IBinder service = sCache.get(name);
        if (service != null) {
            return service;
        } else {
            // 获取的是 ServiceManagerProxy
            return getIServiceManager().getService(name);
        }
    } catch (RemoteException e) {
        Log.e(TAG, "error in getService", e);
    }
    return null;
}

//name = "activity"
public IBinder getService(String name) throws RemoteException {
    Parcel data = Parcel.obtain();
    Parcel reply = Parcel.obtain();
    data.writeInterfaceToken(IServiceManager.descriptor);
    data.writeString(name);
    // 见 3.2.2
    mRemote.transact(GET_SERVICE_TRANSACTION, data, reply, 0);
    // 见 3.2.3
    IBinder binder = reply.readStrongBinder();
    reply.recycle();
    data.recycle();
    return binder;
}
```

### 3.2.2 svcmgr_handler
忽略中间的调用过程，直接看下 service_manager 查出后的执行过程。
```c++
//service_manager.c
int svcmgr_handler(struct binder_state *bs,
                   struct binder_transaction_data *txn,
                   struct binder_io *msg,
                   struct binder_io *reply)
{
    struct svcinfo *si;
    uint16_t *s;
    size_t len;
    uint32_t handle;
    uint32_t strict_policy;
    int allow_isolated;
    ...
    switch(txn->code) {
    case SVC_MGR_GET_SERVICE:
    case SVC_MGR_CHECK_SERVICE:
        s = bio_get_string16(msg, &len);
        if (s == NULL) {
            return -1;
        }
        // 根据"activity"查出 handle
        handle = do_find_service(bs, s, len, txn->sender_euid, txn->sender_pid);
        if (!handle)
            break;
        bio_put_ref(reply, handle);
        return 0;
    ...
    }

    bio_put_uint32(reply, 0);
    return 0;
}

void bio_put_ref(struct binder_io *bio, uint32_t handle)
{
    struct flat_binder_object *obj;

    if (handle)
        obj = bio_alloc_obj(bio);
    else
        obj = bio_alloc(bio, sizeof(*obj));

    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_HANDLE;
    obj->handle = handle;
    obj->cookie = 0;
}
```
这里往 reply 中写入了两个数据，一个是 flat_binder_object，其 type 为 BINDER_TYPE_HANDLE，其 handle 则是驱动为 ActivityManagerService 的 binder_node 所创建的一个引用 binder_ref 的句柄。Service Manager 反馈时，驱动会根据 handle 在 Service Manager 的 proc 下查出 binder_ref，通过 binder_ref->node 取出 ActivityManagerService 的 binder_node，然后在请求线程所在进程的 proc 下创建一个新的 binder_ref，然后返回这个新创建的 binder_ref 的 handle 字段。

也就是说，一个服务对象的 binder_node 只有一个，位于创建服务的进程的 proc 下，而其他所有进程如果想引用该服务都会在其对应进程的 proc 下创建自己的 binder_ref。

### 3.2.3 readStrongBinder

调用完成后会执行 reply.readStrongBinder()，该方法是一个 native 方法 android_os_Parcel_readStrongBinder。

```c++
// android_os_Parcel.cpp
static jobject android_os_Parcel_readStrongBinder(JNIEnv* env, jclass clazz, jlong nativePtr)
{
    Parcel* parcel = reinterpret_cast<Parcel*>(nativePtr);
    if (parcel != NULL) {
        return javaObjectForIBinder(env, parcel->readStrongBinder());
    }
    return NULL;
}
```
parcel->readStrongBinder 会创建一个 BpBinder 对象，传入 handle 作为构造参数。javaObjectForIBinder 会创建一个 android.os.BinderProxy 的 Java 对象，并将 BpBinder 对象的地址赋给 BinderProxy 的 mObject 字段。

### 3.2.4 IActivityManager#asInterface
```java
// ActivityManagerNative.java
// obj = BinderProxy 对象
static public IActivityManager asInterface(IBinder obj) {
    if (obj == null) {
        return null;
    }
    IActivityManager in =
        (IActivityManager)obj.queryLocalInterface(descriptor);
    if (in != null) {
        return in;
    }
    // 最终返回 ActivityManagerProxy
    return new ActivityManagerProxy(obj);
}
```

## 3.3 ActivityManagerProxy#startActivity
```java
// ActivityManagerNative.java
public int startActivity(IApplicationThread caller, String callingPackage, Intent intent,
        String resolvedType, IBinder resultTo, String resultWho, int requestCode,
        int startFlags, ProfilerInfo profilerInfo, Bundle options) throws RemoteException {
    Parcel data = Parcel.obtain();
    Parcel reply = Parcel.obtain();
    ...
    mRemote.transact(START_ACTIVITY_TRANSACTION, data, reply, 0);
    reply.readException();
    int result = reply.readInt();
    reply.recycle();
    data.recycle();
    return result;
}
```
省略掉中间过程，直接看看 binder 驱动如何操作。驱动从取出 handle 后，在当前进程的 proc 下查找 binder_ref，binder_ref->node 便是 target_node，其中的 cookie 字段即是 BBinder 的地址。

回到 IPCThreadState.cpp，在执行 BR_TRANSACTION 时会根据 cookie 找到 BBinder 对象，实际上是 JavaBBinder 对象，其 mObject 字段指向 ActivityManagerService 的 Java 对象。
```c++
if (tr.target.ptr) {
    // We only have a weak reference on the target object, so we must first try to
    // safely acquire a strong reference before doing anything else with it.
    if (reinterpret_cast<RefBase::weakref_type*>(
            tr.target.ptr)->attemptIncStrong(this)) {
        // 见 3.3.1
        error = reinterpret_cast<BBinder*>(tr.cookie)->transact(tr.code, buffer,
                &reply, tr.flags);
        reinterpret_cast<BBinder*>(tr.cookie)->decStrong(this);
    } else {
        error = UNKNOWN_TRANSACTION;
    }

}
```
### 3.3.1 BBinder::transact
```c++
// code = START_ACTIVITY_TRANSACTION
status_t BBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    data.setDataPosition(0);

    status_t err = NO_ERROR;
    switch (code) {
        case PING_TRANSACTION:
            reply->writeInt32(pingBinder());
            break;
        default:
            // JavaBBinder 继承 BBinder，见 3.3.2
            err = onTransact(code, data, reply, flags);
            break;
    }

    if (reply != NULL) {
        reply->setDataPosition(0);
    }

    return err;
}
```
### 3.3.2 JavaBBinder::onTransact
```c++
// android_os_Binder.cpp
// code = START_ACTIVITY_TRANSACTION
virtual status_t onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0)
{
    JNIEnv* env = javavm_to_jnienv(mVM);

    IPCThreadState* thread_state = IPCThreadState::self();
    const int32_t strict_policy_before = thread_state->getStrictModePolicy();

    // 执行 Java 对象的 execTransact 方法，见 3.3.3
    jboolean res = env->CallBooleanMethod(mObject, gBinderOffsets.mExecTransact,
        code, reinterpret_cast<jlong>(&data), reinterpret_cast<jlong>(reply), flags);
    ...
    return res != JNI_FALSE ? NO_ERROR : UNKNOWN_TRANSACTION;
}
```
### 3.3.3 Binder#execTransact
```java
// Binder.java
// code = START_ACTIVITY_TRANSACTION
private boolean execTransact(int code, long dataObj, long replyObj,
        int flags) {
    Parcel data = Parcel.obtain(dataObj);
    Parcel reply = Parcel.obtain(replyObj);
    
    boolean res;
    ...
    try {
        res = onTransact(code, data, reply, flags);
    } catch (RemoteException e) {
      ...
    }
    ...
    return res;
}
```
最终调用 ActivityManagerSerivce 的 onTransact 方法。