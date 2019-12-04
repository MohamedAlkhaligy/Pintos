#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "pagedir.h"
#include <console.h>

#include "userprog/process.h"
#include "threads/vaddr.h"

#define DEBUG false

static void syscall_handler(struct intr_frame *);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);


struct lock write_lock;

void syscall_init(void)
{
      lock_init(&write_lock);
      intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
      if (DEBUG)
            printf("enter syscall handler\n");
      if (DEBUG)
            printf("syscode %p\n", f->esp);
      if (DEBUG)
            printf("syscode %d\n", *(int *)f->esp);
            
      int sys_code = *(int *)f->esp;
      switch (*(int *)f->esp)
      {
      case SYS_HALT:
      {
            halt();
            break;
      }
      case SYS_EXIT:
      {
            if (DEBUG)
                  printf("enter exit system call\n");
            int status = *((int *)f->esp + 1);
            exit(status);
            break;
      }
      case SYS_EXEC:
      {
            break;
      }
      case SYS_WAIT:
      {
            break;
      }
      case SYS_CREATE:
      {
            break;
      }

      case SYS_REMOVE:
      {
            break;
      }
      case SYS_OPEN:
      {
            break;
      }
      case SYS_FILESIZE:
      {
            break;
      }
      case SYS_READ:
      {
            break;
      }
      case SYS_WRITE:
      {
            if (DEBUG)
                  printf("enter write system call\n");
            int fd = *((int *)f->esp + 1);
            if (DEBUG)
                  printf("fd: %d\n", fd);
            void *buffer = (void *)(*((int *)f->esp + 2));
            if (DEBUG)
                  printf("buffer: %x\n", buffer);
            unsigned size = *((unsigned *)f->esp + 3);
            if (DEBUG)
                  printf("size: %dl\n", size);
            //run the syscall, a function of your own making
            //since this syscall returns a value, the return value should be stored in f->eax
            f->eax = write(fd, buffer, size);
            break;
      }
      case SYS_SEEK:
      {
            break;
      }
      case SYS_TELL:
      {
            break;
      }
      case SYS_CLOSE:
      {
            break;
      }
      }
}

void halt(void)
{
      shutdown_power_off();
}

void exit(int status)
{
      if (DEBUG)
            printf("enter exit system call\n");
      struct thread *current = thread_current();
      current->exit_status = status;
      printf("%s: exit(%d)\n", current->name, status);
      thread_exit();
}

pid_t exec(const char *cmd_line)
{
}

int wait(pid_t pid)
{
}
bool create(const char *file, unsigned initial_size)
{
}

bool remove(const char *file) {}
int open(const char *file) {}
int filesize(int fd) {}
int read(int fd, void *buffer, unsigned size) {}
int write(int fd, const void *buffer, unsigned size)
{

      if (fd == 1)
      {
            if (DEBUG)
                  printf("enter write system call\n");
            lock_acquire(&write_lock);
            char *start = buffer;
            putbuf(buffer, size);
            char *end = buffer;
            lock_release(&write_lock);
            if (DEBUG)
                  printf("put in buffer\n");
            return end - start;
      }
      return 0;
}
void seek(int fd, unsigned position) {}
unsigned tell(int fd) {}
void close(int fd) {}
