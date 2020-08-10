---
layout: post
title: 'Android Binder'
date: 2020-08-07
author: 'withparadox2'
catalog: true
tags:
  - Android
---

# 1 Service Manager成为Context Manager

Binder初始化及Service Manager成为Context Manager。 

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
当内核加载驱动时便会执行`device_initcall`所传入的方法`binder_init`进行初始化。在该方法中最重要的一步便是调用`mis_register`进行注册，而且`binder_miscdev`也指定了设备的名字为`binder`以及一个包含文件操作方法的结构体`binder_fops`。后面用户便可以通过系统调用如`open`, `ioctl`打开并与驱动进行交互了。

## 1.2 main
```c
// frameworks/native/cmds/servicemanager/service_manager.c
int main(int argc, char **argv)
{
    struct binder_state *bs;

    // 打开binder驱动，指定内存大小为128kb，见1.3
    bs = binder_open(128*1024);
    if (!bs) {
        ALOGE("failed to open binder driver\n");
        return -1;
    }

    // 成为Context Manager，见1.4
    if (binder_become_context_manager(bs)) {
        ALOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }
    ...
    // 进入循环，等待请求，见1.5
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
    // 会执行binder驱动里的binder_open，返回的fd为文件句柄，用来和binder进行通信，见1.3.1
    bs->fd = open("/dev/binder", O_RDWR);
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open device (%s)\n",
                strerror(errno));
        goto fail_open;
    }

    // 检测和binder驱动的版本是否相同，见1.3.2
    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        fprintf(stderr, "binder: kernel driver version (%d) differs from user space version (%d)\n", vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;
    }

    bs->mapsize = mapsize;
    // 见1.3.3
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

  // current为发起系统调用的进程
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
  // 保存proc，后面mmap或ioctl时可取出
  filp->private_data = proc;
  mutex_unlock(&binder_lock);
  ...
  return 0;
}
```
每个进程在与驱动交互之前都会进行open和mmap操作，binder驱动会在内核为其创建一个proc对象，并进行初始化，之后会将proc对象记录在binder_procs这个列表里。filp为file pointer，在调用open之前，内核会将filp->private_data置为NULL，该字段可以用来保存数据，以便在后面取出。

其中`proc->todo`用来保存待处理的任务，`proc->wait`则用来进行休眠。当没有任务时服务提供者就会休眠，等待其他线程调用`wake_up_interruptible(wait)`来唤醒。后面还将出现thread对象，它也包含`todo`和`wait`两个变量。

### 1.3.2 ioctl (获取binder版本)
```c
// kernel/drivers/android/binder.c
// cmd = BINDER_VERSION = _IOWR('b', 9, struct binder_version)
// arg = &vers
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret;
  // 取出在binder_open时保存的proc
  struct binder_proc *proc = filp->private_data;
  struct binder_thread *thread;
  // 参数arg所指向内容的大小
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
arg是一个指向位于用户空间的struct binder_version的指针，而所指向内容的大小信息保存在cmd中，通过_IOC_SIZE可以解析出来。

由于arg指向的地址位于用户空间，不能直接操作，所以这里通过put_user将版本信息保存到结构体的protocol_version字段里。

### 1.3.3 binder_mmap
```c
// kernel/drivers/android/binder.c
// vma包含用户空间的虚拟内存分配信息
static int binder_mmap(struct file *filp, struct vm_area_struct *vma)
{
  int ret;
  // 内核空间虚拟内存分配信息
  struct vm_struct *area;
  // 取出proc
  struct binder_proc *proc = filp->private_data;
  const char *failure_string;
  struct binder_buffer *buffer;
 
  // 保证最大分配不超过4Mb，这里请求时只有128Kb
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
  
  // 先分配1个页面的物理内存，见1.3.3.1
  if (binder_update_page_range(proc, 1, proc->buffer, proc->buffer + PAGE_SIZE, vma)) {
    ret = -ENOMEM;
    failure_string = "alloc small buf";
    goto err_alloc_small_buf_failed;
  }
  // 不进行初始化???
  buffer = proc->buffer;
  INIT_LIST_HEAD(&proc->buffers);
  // 将buffer加入到proc->buffers列表中
  list_add(&buffer->entry, &proc->buffers);
  buffer->free = 1;
  // 将该buffer加入到未使用的buffer树中，见1.3.3.2
  binder_insert_free_buffer(proc, buffer);
  // 用于异步请求的buffer只有一半大小，具体如何使用???
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
调用get_vm_area在内核空间分配一段虚拟内存，最大不超过4Mb。由于用户空间和内核空间分配的这块虚拟内存指向同一处物理内存，因此知道这二者之差便可以将其进行地址转换。例如，如果知道内核空间地址为addr1，那么用户空间的地址便可通过简单的加法计算出来 proc->user_buffer_offset + addr1。

这里有个问题，buffer是一个指向struct binder_buffer的指针，而proc->buffer指向的是一段连续的虚拟内存，为何可以直接将proc->buffer赋值给buffer而不用初始化？

事实上，在binder_update_page_range中已经分配了一段大小为一个页面的物理内存，并且初始化为0。buffer的一个应用是通过binder_buffer_size计算大小，这一步并不需要多余的初始化：

```c
// kernel/drivers/android/binder.c
static size_t binder_buffer_size(struct binder_proc *proc,
         struct binder_buffer *buffer)
{
  if (list_is_last(&buffer->entry, &proc->buffers))
    // 用整段buffer的结束地址减去buffer结构体的结束地址
    return proc->buffer + proc->buffer_size - (void *)buffer->data;
  else
    return (size_t)list_entry(buffer->entry.next,
      struct binder_buffer, entry) - (size_t)buffer->data;
}
```
buffer是连续的。buffer指向的内存包含了buffer的结构体，所以buffer的有效内存大小则是下一个buffer的起始地址减去当前buffer的结构体的结束地址，而buffer->data是一个位于结构体末尾的8位数组，因此buffer->data便可表示结构体的结束地址。

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

每个buffer包含一个entry字段，加入到proc->buffers列表中的也是entry字段。list_entry定义如下：

```c
#define list_entry(ptr, type, member) \
  container_of(ptr, type, member)
 
#define container_of(ptr, type, member) ({\
  const typeof( ((type *)0)->member ) *__mptr = (ptr); \  
  (type *)( (char *)__mptr - offsetof(type,member) );}) \
```
知道member和指向member的指针ptr，便可以计算出指向包含member的结构体type的指针。这种操作在其他内核数据结构中也常见，包括红黑树。

#### 1.3.3.1 binder_update_page_range

```c++
// kernel/drivers/android/binder.c
// allocate = 1 当为0时表示释放物理内存
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
    // 这里取出第0个页面
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
问题：allocate等于0的情况？

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

  // 计算计划插入的buffer有效空间大小
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
    // 见1.4.1
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);
}
```

### 1.4.1 ioctl (BINDER_SET_CONTEXT_MGR)

```c
// kernel/drivers/android/binder.c

static struct binder_node *binder_context_mgr_node;
static uid_t binder_context_mgr_uid = -1;

// cmd = BINDER_SET_CONTEXT_MGR = _IOW('b', 7, int)
// arg = 指向4字节内存，内容为0
static long binder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  int ret;
  struct binder_proc *proc = filp->private_data;
  struct binder_thread *thread;
  // arg指向内存大小，这里大小为4，内容为0
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
    // binder_context_mgr_uid默认为-1
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
    // 创建一个binder_node，见1.4.1.1
    binder_context_mgr_node = binder_new_node(proc, NULL, NULL);
    if (binder_context_mgr_node == NULL) {
      ret = -ENOMEM;
      goto err;
    }
    // 将各种引用加1，干什么用？？？
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
  // 将新创建的node插入红黑树中，其父节点为parent
  rb_link_node(&node->rb_node, parent, p);
  rb_insert_color(&node->rb_node, &proc->nodes);
  // 每次创建debug_id加1
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
该方法创建一个新的binder_node，插入到proc->nodes中，然后进行初始化。

## 1.5 binder_loop

```c
// frameworks/native/cmds/servicemanager/binder.c
// bs = binder_open的返回值
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
    // 见1.5.1
    binder_write(bs, readbuf, sizeof(uint32_t));

    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;

        // 见1.5.2
        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }

        // 见1.5.3
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
// data = readbuf，大小为32的4字节数组，其中readbuf[0] = BC_ENTER_LOOPER
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
arg = 指向binder_write_read结构体，内容如下：
{
  write_size: 4,
  write_consumed: 0,
  write_buffer: 大小32的数组，[BC_ENTER_LOOPER, ... ],
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
  // 查找或创建当前线程的结构体，见1.5.1.1
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
    // 将用户空间的数据拷贝到内核空间，但是bwr.write_buffer目前依然指向用户空间 
    if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    // write_size为4
    if (bwr.write_size > 0) {
      // 见1.5.1.2
      ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
      if (ret < 0) {
        // 如果出错，则设置read_consumed为0，意即驱动没有写入任何数据，返回
        bwr.read_consumed = 0;
        if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
          ret = -EFAULT;
        goto err;
      }
    }
    
    // bwr.read_size为0，跳过
    if (bwr.read_size > 0) {
      ...
    }
    
    // 把bwr拷贝到用户空间，准备返回到用户空间
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
执行完成后，返回到1.5，继续执行for循环里面的内容。

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
  // 没有找到，则新创建一个binder_thread
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
在proc->threads中根据发起请求线程的pid查找binder_thread对象，如果没找到，则创建一个，并插入到proc->threads，然后进行初始化。

##### 1.5.1.2 binder_thread_write
```c
// kernel/drivers/android/binder.c
// buffer = 指向用户空间的32位数组，[BC_ENTER_LOOPER, ... ]
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
    // 从用户空间取出前4个字节为 BC_ENTER_LOOPER
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
      // 如果已经注册了，则写入错误flag，何用???
      if (thread->looper & BINDER_LOOPER_STATE_REGISTERED) {
        thread->looper |= BINDER_LOOPER_STATE_INVALID;
        binder_user_error("binder: %d:%d ERROR:"
          " BC_ENTER_LOOPER called after "
          "BC_REGISTER_LOOPER\n",
          proc->pid, thread->pid);
      }
      // 标识该thread已经就绪
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
此步执行完后bwr.write_consumed被改为4。

### 1.5.2 ioctl
```c
// kernel/drivers/android/binder.c
/*
cmd = BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read)
arg = 指向binder_write_read结构体，内容如下：
{
  write_size: 4,
  write_consumed: 4,
  write_buffer: 32个4字节的数组，[BC_ENTER_LOOPER, ... ],
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
    // 将用户空间的数据拷贝到内核空间，但是bwr.write_buffer目前依然指向用户空间 
    if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
      ret = -EFAULT;
      goto err;
    }
    // bwr.write_size为4
    if (bwr.write_size > 0) {
      // 由于write_consumed和write_size都为4，所以进去后不会执行相关代码
      ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
      ...
    }
    
    // bwr.read_size为32*4
    if (bwr.read_size > 0) {
      // 见1.5.2.1
      ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
      // 如果进程的todo里面还有任务要做，那么唤醒工作线程
      if (!list_empty(&proc->todo))
        wake_up_interruptible(&proc->wait);
      if (ret < 0) {
        if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
          ret = -EFAULT;
        goto err;
      }
    }
    
    // 把bwr拷贝到用户空间，准备返回到用户空间
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
// buffer = 指向用户空间的4字节数组，[BC_ENTER_LOOPER, ... ]
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
    // 由于consumed位0，这里向buffer里面写入一个32位整数BR_NOOP
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  // 还没有任务可处理，这里为true
  wait_for_proc_work = thread->transaction_stack == NULL &&
        list_empty(&thread->todo);
  ...
  // 将当前线程的状态置为等待，稍后如果发现有任务会解除该状态
  thread->looper |= BINDER_LOOPER_STATE_WAITING;
  // 如果当前线程自己没有任务可处理，说明已经准备处理进程的任务，于是这里将ready_threads加1
  if (wait_for_proc_work)
    proc->ready_threads++;
  mutex_unlock(&binder_lock);
  if (wait_for_proc_work) {
    // 只有binder线程能到这里来取任务，如果不是则记录异常
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
      // 对于阻塞情况，则等待唤醒，当binder_has_proc_work为true时才往后面执行
      // binder_has_proc_work会检查proc的todo是否有任务。

      // 目前我们就停在这里等待唤醒。
      ret = wait_event_interruptible_exclusive(proc->wait, binder_has_proc_work(proc, thread));
  } else {
    // 此时不会走这里。
    // binder_has_thread_work会检测thread的todo是否有任务
    if (non_block) {
      if (!binder_has_thread_work(thread))
        ret = -EAGAIN;
    } else
      ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
  }
  // 当线程被唤醒后会获取锁，在释放之前，其他线程即使被唤醒了也阻塞在这里。
  // 只有当获取锁的线程重新进入上面retry释放锁后，其他线程方有机会获取锁。
  mutex_lock(&binder_lock);
  // 如果此前线程没有自己的任务，这里准备执行进程任务了，于是可用的线程需要减1，并
  // 删除线程的等待标识。
  if (wait_for_proc_work)
    proc->ready_threads--;
  thread->looper &= ~BINDER_LOOPER_STATE_WAITING;
  ...
}
```
当在wait_event_interruptible_exclusive阻塞等待唤醒时，驱动已经往read_buffer里面写入一个整数BR_NOOP。

# 2 