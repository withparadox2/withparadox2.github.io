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

# 2 注册ActivityManagerService

Zygote进程会创建SystemServer进程并调用SystemServer.main方法。下面从main方法开始看。

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
// service = ActivityManagerService对象
// allowIsolated = true
public static void addService(String name, IBinder service, boolean allowIsolated) {
  try {
    // addService 见2.1.2
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
BinderInternal.getContextObject()是一个native方法，通过它得到一个IBinder对象。这里obj是一个BinderProxy对象，queryLocalInterface返回为null，因此我们得到的是一个ServiceManagerProxy对象。

下面看下如果获得IBinder对象。

### 2.1.1 BinderInternal.getContextObject
```c++
// android_util_binder.cpp
static jobject android_os_BinderInternal_getContextObject(JNIEnv* env, jobject clazz)
{
   // 见2.1.1.1
    sp<IBinder> b = ProcessState::self()->getContextObject(NULL);
  // 见2.1.1.2
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
gProcess是一个单例，在初始化时会调用open_driver()打开binder驱动，并将文件符保存至mDriverFD字段中。下面看下getContextObject的实现。

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

  // 根据handle在一个vector中查找，找不到则创建一个handle_entry，字段为null
  handle_entry* e = lookupHandleLocked(handle);

  if (e != NULL) {
    // b 为 NULL
    IBinder* b = e->binder;
    if (b == NULL || !e->refs->attemptIncWeak(this)) {
      if (handle == 0) {
        // 检测context manager是否已经注册
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
getContextObject返回的是一个构造参数为0的BpBinder对象。

#### 2.1.1.2 javaObjectForIBinder
```c++
// android_util_Binder.cpp
// val = new BpBinder(0)
jobject javaObjectForIBinder(JNIEnv* env, const sp<IBinder>& val)
{
  if (val == NULL) return NULL;

  // 检测是否为android.os.Binder的子类
  if (val->checkSubclass(&gBinderOffsets)) {
    jobject object = static_cast<JavaBBinder*>(val.get())->object();
    return object;
  }

  // For the rest of the function we will hold this lock, to serialize
  // looking/creation of Java proxies for native Binder proxies.
  AutoMutex _l(mProxyLock);

  // Someone else's...  do we know about it?
  // BpBinder是个纯C++对象，肯定不走这里
  jobject object = (jobject)val->findObject(&gBinderProxyOffsets);
  if (object != NULL) {
    ...
  }

  // 创建一个android.os.BinderProxy的Java对象
  object = env->NewObject(gBinderProxyOffsets.mClass, gBinderProxyOffsets.mConstructor);
  if (object != NULL) {
    LOGDEATH("objectForBinder %p: created new proxy %p !\n", val.get(), object);
    // 将BpBinder的地址赋给BinderProxy的mObject字段
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

  // BinderProxy对象
  return object;
}
```
### 2.1.2 ServiceManagerProxy#addService
```java
// frameworks/base/core/java/android/os/ServiceManagerNative.java
// name = "activity"
// service = ActivityManagerService对象
// allowIsolated = true
public void addService(String name, IBinder service, boolean allowIsolated)
      throws RemoteException {
  // 见2.1.3  
  Parcel data = Parcel.obtain();
  Parcel reply = Parcel.obtain();
  // 见2.1.4
  data.writeInterfaceToken(IServiceManager.descriptor);
  data.writeString(name);
  data.writeStrongBinder(service);
  data.writeInt(allowIsolated ? 1 : 0);
  // 见2.1.5
  mRemote.transact(ADD_SERVICE_TRANSACTION, data, reply, 0);
  reply.recycle();
  data.recycle();
}
```
这里的mRemote便为构造ServiceManagerProxy时传入的BinderProxy对象，它的mObject字段指向一个BpBinder的C++对象，该BpBinder对象的handle为0。

往data中写入的内容包括：
- 字符串："android.os.IServiceManager"
- 字符串："activity",
- flat_binder_object结构体: 
```
{
 flags: 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS,
 type: BINDER_TYPE_BINDER,
 binder: 弱引用,
 cookie: 指向Binder对象指针,
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
obtain()会先从缓存池中获取Parcel，如果没有则新创建一个Parcel对象，传入参数为0，接下来调用native方法nativeCreate来创建一个native对象，并将对象指针保存到mNativePtr中。

```c++
// android_os_Parcel.cpp
static jlong android_os_Parcel_create(JNIEnv* env, jclass clazz)
{
    Parcel* parcel = new Parcel();
    return reinterpret_cast<jlong>(parcel);
}
```
### 2.1.4 向Parcel写入数据
```java
// Parcel.java
// interfaceName = "android.os.IServiceManager"
public final void writeInterfaceToken(String interfaceName) {
  nativeWriteInterfaceToken(mNativePtr, interfaceName);
}
```
调用native方法。
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
写入字符串时首先写入字符串长度，接着写入字符串内容，最后再写入一个整数0。

data.writeString(name)和data.writeInt(allowIsolated ? 1 : 0)与writeInterfaceToken类似，不做分析，下面看看data.writeStrongBinder：

```c++
// android_os_Parcel.cpp
// object = ActivityManagerService对象
static void android_os_Parcel_writeStrongBinder(JNIEnv* env, jclass clazz, jlong nativePtr, jobject object)
{
  Parcel* parcel = reinterpret_cast<Parcel*>(nativePtr);
  if (parcel != NULL) {
  // ibinderForJavaObject 见2.1.4.1
  // writeStrongBinder 见2.1.4.2
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
// obj = ActivityManagerService对象
sp<IBinder> ibinderForJavaObject(JNIEnv* env, jobject obj)
{
  if (obj == NULL) return NULL;

  // 由于ActivityManagerService继承Binder对象，进入该分支
  if (env->IsInstanceOf(obj, gBinderOffsets.mClass)) {
     // Java端的Binder对象会持有一个mObject字段，指向
    // native端的JavaBBinderHolder对象，见2.1.4.1.1
    JavaBBinderHolder* jbh = (JavaBBinderHolder*)
      env->GetLongField(obj, gBinderOffsets.mObject);
    // 见2.1.4.1.2
    return jbh != NULL ? jbh->get(env, obj) : NULL;
  }

  // 对于非服务类，则继承BinderProxy，前面已经讲过
  if (env->IsInstanceOf(obj, gBinderProxyOffsets.mClass)) {
    return (IBinder*)
      env->GetLongField(obj, gBinderProxyOffsets.mObject);
  }

  ALOGW("ibinderForJavaObject: %p is not a Binder object", obj);
  return NULL;
}
```
最终返回一个JavaBBinder对象，其mObject字段引用ActivityManagerService对象。

##### 2.1.4.1.1 android_os_Binder_init
Java端Binder类的构造方法会调用一个native方法init，在该native方法中会创建一个JavaBBinderHolder的native对象，并将其地址赋给Java对象的mObject字段。
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

// obj = ActivityManagerService对象
sp<JavaBBinder> get(JNIEnv* env, jobject obj)
{
  AutoMutex _l(mLock);
  // mBinder是一个弱引用，第一次调用返回NULL
  sp<JavaBBinder> b = mBinder.promote();
  if (b == NULL) {
    b = new JavaBBinder(env, obj);
    mBinder = b;
  }

  return b;
}
```
这里创建一个JavaBBinder对象，保存ActivityManagerService对象到mObject字段中。

#### 2.1.4.2 Parcel#writeStrongBinder
```c++
// Parcel.cpp
// val = JavaBBinder对象
status_t Parcel::writeStrongBinder(const sp<IBinder>& val)
{
 // 见2.1.4.2.1
  return flatten_binder(ProcessState::self(), val, this);
}
```
##### 2.1.4.2.1 Parcel#flatten_binder
```c++
// Parcel.cpp
// binder = JavaBBinder对象
status_t flatten_binder(const sp<ProcessState>& /*proc*/,
    const sp<IBinder>& binder, Parcel* out)
{
  flat_binder_object obj;

  obj.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
  if (binder != NULL) {
    // JavaBBinder继承BBinder，所以localBinder返回自身
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
如果binder是BBinder，那么它标识的服务提供方，obj.cookie保存的是指向该binder的实际指针；如果binder是Bpinder，那么它标识的服务使用方，obj.handle保存的实际Binder在驱动中的一个引用。
```c++
// Parcel.cpp
/*
val = {
 flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS,
 type: BINDER_TYPE_BINDER,
 binder: 弱引用,
 cookie: 指向Binder对象指针,
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
      // 记录flat_binder_object的在buffer中的位置
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
如果空间不够则增大空间，并将val写入到Parcel中，同时记录了val在buffer中的位置，后面在binder驱动中会进行修改。

### 2.1.5 BinderProxy#transact
```java
// Binder.java
// code = IServiceManager.ADD_SERVICE_TRANSACTION
// data = 见2.1.2注释
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
// dataObj = 写入的Parcel，见2.1.2注释
// flags = 0
static jboolean android_os_BinderProxy_transact(JNIEnv* env, jobject obj,
        jint code, jobject dataObj, jobject replyObj, jint flags) // throws RemoteException
{
  if (dataObj == NULL) {
    jniThrowNullPointerException(env, NULL);
    return JNI_FALSE;
  }
  // 从Java对象中取出native对象
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
 // 见2.1.5.2
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
// data = 写入的Parcel，见2.1.2注释
// reply = 待写入的Parcel
// flags = 0
status_t BpBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
  if (mAlive) {
  // 见2.2
    status_t status = IPCThreadState::self()->transact(
      mHandle, code, data, reply, flags);
    if (status == DEAD_OBJECT) mAlive = 0;
    return status;
  }

  return DEAD_OBJECT;
}
```
IPCThreadState为每个线程维护了一个实例，通过IPCThreadState::self()获取。在IPCThreadState初始化时，会将ProcessState的进程单例保存到mProcess字段中。

## 2.2 IPCThreadState#transact
```c++
// IPCThreadState.cpp
// handle = 0
// code =  IServiceManager.ADD_SERVICE_TRANSACTION
// data = 写入的Parcel，见2.1.2注释
// reply = 待写入的Parcel
// flags = 0
status_t IPCThreadState::transact(int32_t handle,
                                  uint32_t code, const Parcel& data,
                                  Parcel* reply, uint32_t flags)
{
  flags |= TF_ACCEPT_FDS;
 if (err == NO_ERROR) {
    // 见2.2.1
    err = writeTransactionData(BC_TRANSACTION, flags, handle, code, data, NULL);
 } 
  ...
 // 不是非阻塞模式，进入该分支
  if ((flags & TF_ONE_WAY) == 0) {
    // reply不为NULL
    if (reply) {
      // 见2.2.2   
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
// data = 写入的Parcel，见2.1.2注释
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
    // 存储binder对象位置的数组字节大小
    tr.offsets_size = data.ipcObjectsCount()*sizeof(binder_size_t);
  // binder对象的对象位置的数组
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
  // mOut是发给binder驱动的数据  
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
  // 见2.2.3
    if ((err=talkWithDriver()) < NO_ERROR) break;
    if (mIn.dataAvail() == 0) continue;
    cmd = (uint32_t)mIn.readInt32();
    switch (cmd) {
    // 第二个指令BR_TRANSACTION_COMPLETE  
    case BR_TRANSACTION_COMPLETE:
      if (!reply && !acquireResult) goto finish;
      // 跳出switch，继续循环
      break;
      ...
    default:
      // 第一个指令BR_NOOP，executeCommand不会进行任何操作
      err = executeCommand(cmd);
      if (err != NO_ERROR) goto finish;
      break;
    }
  }
 ...
  return err;
}
```
执行过程为调用talkWithDriver，向驱动发送数据，然后读取驱动写入的数据，根据cmd进行操作。

第一次talkWithDriver结束后，mIn被驱动写入两个整数：BR_NOOP和BR_TRANSACTION_COMPLETE。

BR_NOOP不会执行任何操作，BR_TRANSACTION_COMPLETE分支执行后继续循环。于是第二次调用talkWithDriver。

这一次write_size为0，read_size不为0。再次发起系统调用见2.2.8。

### 2.2.3 talkWithDriver
```c++
// IPCThreadState.cpp
// doReceive = true
status_t IPCThreadState::talkWithDriver(bool doReceive)
{
  // mProcess即为ProcessState
  if (mProcess->mDriverFD <= 0) {
    return -EBADF;
  }
  
  binder_write_read bwr;
  
  // Is the read buffer empty?
	// 如果为true说明驱动写入的数据已经读取完了，或者根本就没数据
	// 当前情况为true
  const bool needRead = mIn.dataPosition() >= mIn.dataSize();
  
	// outAvail = mOut.dataSize()
  const size_t outAvail = (!doReceive || needRead) ? mOut.dataSize() : 0;
  
  bwr.write_size = outAvail;
  bwr.write_buffer = (uintptr_t)mOut.data();

  // This is what we'll read.
  if (doReceive && needRead) {
    // 初始化IPCThreadState时，mIn和mOut容量都为256
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
		// 系统调用，见2.2.4
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
      // 当读完后，position就和size相同了，发起第二次talkWithDriver时needRead就为true
      mIn.setDataSize(bwr.read_consumed);
      mIn.setDataPosition(0);
    }
    return NO_ERROR;
  }
  
  return err;
}
```
发起系统调用，从2.2.7系统调用返回后，write_buffer全部消耗完，read_buffer中写入两个整数，BR_NOOP和BR_TRANSACTION_COMPLETE。接着返回到2.2.2 waitForResponse。

### 2.2.4 binder_ioctl
```c++
// kernel/drivers/android/binder.c
/*
cmd = BINDER_WRITE_READ
arg = 指向用户空间的binder_write_read结构体：
{
  write_size: write_buffer大小,
  write_consumed: 0,
  write_buffer: [BC_TRANSACTION, binder_transaction_data对象], // 见2.2.1
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
    // 不为0，见2.2.5
    if (bwr.write_size > 0) {
      ret = binder_thread_write(proc, thread, (void __user *)bwr.write_buffer, bwr.write_size, &bwr.write_consumed);
      if (ret < 0) {
        bwr.read_consumed = 0;
        if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
          ret = -EFAULT;
        goto err;
      }
    }
    // 不为0，见2.2.7
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
// *buffer = [BC_TRANSACTION, binder_transaction_data对象]// 见2.2.1
// size = buffer大小
// *consumed = 0
int binder_thread_write(struct binder_proc *proc, struct binder_thread *thread,
      void __user *buffer, int size, signed long *consumed)
{
  uint32_t cmd;
  void __user *ptr = buffer + *consumed;
  void __user *end = buffer + size;

  while (ptr < end && thread->return_error == BR_OK) {
    //取出cmd为BC_TRANSACTION
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
      // ptr将指向buffer的末尾        
      ptr += sizeof(tr);
      // 见2.2.6      
      binder_transaction(proc, thread, &tr, cmd == BC_REPLY);
      break;
    ...
    }
    }
    // 数据全部消耗，*consumed等于buffer所指向数据的大小
    *consumed = ptr - buffer;
  }
  return 0;
}
```

### 2.2.6 binder_transaction
```c++
// kernel/drivers/android/binder.c
// tr = 指向binder_transaction_data对象 // 见2.2.1
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
      // 第1阶段已经介绍了
      target_node = binder_context_mgr_node;
      if (target_node == NULL) {
        return_error = BR_DEAD_REPLY;
        goto err_no_context_mgr_node;
      }
    }
    // Service Manager进程的proc
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
  // target_thread = null，没有指定线程，那么后续操作的是目标进程的todo  
  if (target_thread) {
    target_list = &target_thread->todo;
    target_wait = &target_thread->wait;
  } else {
    target_list = &target_proc->todo;
    target_wait = &target_proc->wait;
  }

  /* TODO: reuse incoming transaction for reply */
  // 为当前的binder事务分配内存
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
  // Service Manager的proc
  t->to_proc = target_proc;
  // null
  t->to_thread = target_thread;
  // IServiceManager.ADD_SERVICE_TRANSACTION
  t->code = tr->code;
  // TF_ACCEPT_FDS
  t->flags = tr->flags;
  t->priority = task_nice(current);
  // 分配内存，准备将tr->data.ptr->buffer和tr->data.ptr.offsets
  // 指向的用户数据取出来，见2.2.6.1
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
  // buffer存储了两部分数据，这里计算存储offsets的起始地址
  offp = (size_t *)(t->buffer->data + ALIGN(tr->data_size, sizeof(void *)));
  // 将buffer数据取出，具体内容见2.1.2注释
  if (copy_from_user(t->buffer->data, tr->data.ptr.buffer, tr->data_size)) {
    ...
  }
  // 将buffer中所包含的Binder对象位置信息数组offsets取出
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
  // 指向offsets的末尾，也是整个buffer的末尾  
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
    // 取出Binder对象，即起始位置加上一个偏移，这里只有一个对象，内容为：
    // {
    //   flags: 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS,
    //   type: BINDER_TYPE_BINDER,
    //   binder: 弱引用,
    //   cookie: 指向Binder对象指针,
    // }
    fp = (struct flat_binder_object *)(t->buffer->data + *offp);
    switch (fp->type) {
    case BINDER_TYPE_BINDER:
    case BINDER_TYPE_WEAK_BINDER: {
      struct binder_ref *ref;
      // 每个进程都在proc的nodes字段中维护当前进程的binder_node，binder_node
      // 保存了Service的信息，例如地址。驱动会将一个binder_node的引用传递给其他
      // 进程。
      struct binder_node *node = binder_get_node(proc, fp->binder);
      if (node == NULL) {
        // 没有查到则新建一个并插入到proc.nodes中，这里的fp->cookie便是AMS
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
      // 为binder_node创建一个引用，见2.2.6.2
      ref = binder_get_ref_for_node(target_proc, node);
      if (ref == NULL) {
        return_error = BR_FAILED_REPLY;
        goto err_binder_get_ref_for_node_failed;
      }
      // 将类型改为BINDER_TYPE_HANDLE，记住，其他进程持有的都是handle
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
  // 唤醒Service Manager
  if (target_wait)
    // 见2.3
    wake_up_interruptible(target_wait);
  return;
  ...// 错误处理
}
```

唤醒目标线程后，继续返回到2.2.4 binder_ioctl，由于bwr.read_size不为0，进入2.2.7。ServiceManager线程在被唤醒后的执行见2.3。

#### 2.2.6.1 binder_alloc_buf
#### 2.2.6.2 binder_get_ref_for_node

### 2.2.7 binder_thread_read

```c++
if (bwr.read_size > 0) {
  ret = binder_thread_read(proc, thread, (void __user *)bwr.read_buffer, bwr.read_size, &bwr.read_consumed, filp->f_flags & O_NONBLOCK);
  // 内容为空，此时thread->todo不为空
  if (!list_empty(&proc->todo))
    wake_up_interruptible(&proc->wait);
  if (ret < 0) {
    // 将数据读写情况返回给请求方，此时write buffer全部读完，
    if (copy_to_user(ubuf, &bwr, sizeof(bwr)))
      ret = -EFAULT;
    goto err;
  }
}

// buffer = 指向内存的大小为256字节
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
    // 写入BR_NOOP
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  // thread->transaction_stack不为NULL
  // thread->todo也不为空
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
      // 走这里，但是当前线程有任务，binder_has_thread_work执行为true，继续往下执行
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
      // 第一次循环走这里，取出任务，类型为BINDER_WORK_TRANSACTION_COMPLETE
      w = list_first_entry(&thread->todo, struct binder_work, entry);
    else if (!list_empty(&proc->todo) && wait_for_proc_work)
      w = list_first_entry(&proc->todo, struct binder_work, entry);
    else {
      // 第二次循环走这里，由于thread->looper & BINDER_LOOPER_STATE_NEED_RETURN为1，
      // 直接break。
      // 只有在ioctl出错时，thread->looper & BINDER_LOOPER_STATE_NEED_RETURN才为0。
      if (ptr - buffer == 4 && !(thread->looper & BINDER_LOOPER_STATE_NEED_RETURN)) /* no data added */
        goto retry;
      break;
    }

    // 一共256，只写了4个字节，还够，往下执行
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

    // t为NULL，不往下执行，继续循环
    if (!t)
      continue;
    ...
  }

done:
  // 第二次循环跳出后记下数据写入情况，一共写入两个整数：BR_NOOP和BR_TRANSACTION_COMPLETE
  *consumed = ptr - buffer;
  ...
  return 0;
}
```
经过两次循环后，退出icotl，最终返回到2.2.3 talkWithDriver，处理数据读写情况：

### 2.2.8 第二次binder_thread_read
由于第二次iotcl，write size为0，read size不为0，于是再次进入binder_thread_read。

```c++
// buffer = 指向内存的大小为256字节
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
    // 写入BR_NOOP
    if (put_user(BR_NOOP, (uint32_t __user *)ptr))
      return -EFAULT;
    ptr += sizeof(uint32_t);
  }

retry:
  // thread->transaction_stack不为NULL
  // thread->todo为空
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
      // 阻塞在这里，等待ServiceManager
      ret = wait_event_interruptible(thread->wait, binder_has_thread_work(thread));
  }
 ...
}
```
由于事务栈不为空，且待处理任务为空，于是阻塞，等待ServiceManager唤醒。

## 2.3 ServiceManager唤醒后执行过程


在Java中，IBinder是基础接口，Binder和BinderProxy都继承IBinder。服务提供着需要继承Binder，例如ActivityManagerService。而服务调用者则包含一个BinderProxy对象，例如ActivityManagerProxy。服务提供者和服务调用者都需要实现业务接口，二者皆实现IActivityManager。

