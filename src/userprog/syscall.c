#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "pagedir.h"
#include <console.h>
#include <string.h>

#include "userprog/process.h"
#include "threads/vaddr.h"

#include "filesys/filesys.h"
#include "filesys/file.h"

#define DEBUG false


static int
get_user(const uint8_t *uaddr);

static bool
put_user(uint8_t *udst, uint8_t byte);

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

struct lock file_lock;

void syscall_init(void)
{
      lock_init(&file_lock);
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
      if (f->esp == NULL || !is_user_vaddr(f->esp) || get_user(f->esp) == -1)
      {
            exit(-1);
      }
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
            if (DEBUG)
                  printf("enter exec system call\n");
            char *cmd_line = *((char **)f->esp + 1);
            f->eax = exec(cmd_line);
            break;
      }
      case SYS_WAIT:
      {
            if (DEBUG)
                  printf("enter wait system call\n");
            pid_t child_id = *((pid_t *)f->esp + 1);
            f->eax = wait(child_id);
            break;
      }
      case SYS_CREATE:
      {
            if (DEBUG)
                  printf("enter create file system call\n");
            char *name = (char *)(*((char *)f->esp + 1));
            if (DEBUG)
                  printf("name: %x\n", name);
            unsigned size = *((unsigned *)f->esp + 2);
            if (DEBUG)
                  printf("size: %dl\n", size);
            //run the syscall, a function of your own making
            //since this syscall returns a value, the return value should be stored in f->eax
            f->eax = create(name, size);
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
            if (DEBUG)
                  printf("enter read system call\n");
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
            f->eax = read(fd, buffer, size);
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
/*Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h). This
should be seldom used, because you lose some information about possible
deadlock situations, etc*/
void halt(void)
{
      shutdown_power_off();
}

/*Terminates the current user program, returning status to the kernel. If the process’s parent
waits for it (see below), this is the status that will be returned. Conventionally, a status of 0
indicates success and nonzero values indicate errors.*/
void exit(int status)
{
      if (DEBUG)
            printf("enter exit system call\n");
      struct thread *current = thread_current();
      current->exit_status = status;

      thread_exit();
}

/*Runs the executable whose name is given in cmd_line, passing any given arguments, and
returns the new process’s program ID (pid). Must return pid -1, which otherwise should
not be a valid pid, if the program cannot load or run for any reason. Thus, the parent
process cannot return from the exec until it knows whether the child process successfully
loaded its executable. You must use appropriate synchronization to ensure this.*/
pid_t exec(const char *cmd_line)
{
      if (cmd_line != NULL)
      {
            pid_t child_id = process_execute(cmd_line);
            thread_current()->exec_proc = true;
            sema_down(&thread_current()->child_loaded);

            return thread_current()->loaded ? child_id : -1;
      }
      return -1;
}

/*Waits for a child process pid and retrieves the child’s exit status.
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit.
If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception),
wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes 
that have already terminated by the time the parent calls wait, but the kernel must
still allow the parent to retrieve its child’s exit status, or learn that the child was terminated
by the kernel.*/

int wait(pid_t pid)
{
      int status = process_wait(pid);
      return status;
}

bool create(const char *file, unsigned initial_size)
{
      int result = false;
      if (file != NULL)
      {
            lock_acquire(&file_lock);
            result = filesys_create(file, initial_size);
            lock_release(&file_lock);
      }
      else
      {
            exit(-1);
      }
      return result;
}

bool remove(const char *file)
{

}
int open(const char *file)
{

}
int filesize(int fd)
{

}

/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition 
other than end of file). Fd 0 reads from the keyboard using input_getc().
*/
int read(int fd, void *buffer, unsigned size)
{

      if (fd == 0)
      {
            if (DEBUG)
                  printf("enter read function system call\n");
            lock_acquire(&file_lock);
            char *start = buffer;
            for (size_t j = 1; j <= size; j++)
            {
                  char input = input_getc();
                  memcpy(buffer, &input, sizeof(input));
                  buffer = (char *)buffer + sizeof(input);
                  if (input == NULL)
                        break;
            }

            char *end = buffer;
            lock_release(&file_lock);
            return end - start;
      }
      return -1;
}
/*Writes size bytes from buffer to the open file fd. Returns the number of bytes actually 
written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented
by the basic file system. The expected behavior is to write as many bytes as possible up to
end-of-file and return the actual number written, or 0 if no bytes could be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of buffer in
one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is
reasonable to break up larger buffers.) Otherwise, lines of text output by different processes
may end up interleaved on the console, confusing both human readers and our grading
scripts.*/

int write(int fd, const void *buffer, unsigned size)
{

      if (fd == 1)
      {
            if (DEBUG)
                  printf("enter write system call\n");
            lock_acquire(&file_lock);
            char *start = buffer;
            putbuf(buffer, size);
            char *end = buffer;
            lock_release(&file_lock);
            if (DEBUG)
                  printf("put in buffer\n");
            return end - start;
      }
      return -1;
}
void seek(int fd, unsigned position) {}
unsigned tell(int fd) {}
void close(int fd) {}




/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user(const uint8_t *uaddr)
{
      int result;
      asm("movl $1f, %0; movzbl %1, %0; 1:"
          : "=&a"(result)
          : "m"(*uaddr));
      return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte)
{
      int error_code;
      asm("movl $1f, %0; movb %b2, %1; 1:"
          : "=&a"(error_code), "=m"(*udst)
          : "q"(byte));
      return error_code != -1;
}


/** read **/
static bool
readUserAccess(const void *from, int length, const void *to)
{
      if (from < PHYS_BASE && (from + length) < PHYS_BASE)
      {
            for (int i = 0; i < length; i++)
            {
                  if (get_user((uint8_t *)from + i) == -1)
                  {
                        return false;
                  }
                  *((uint8_t *)to + i) = (uint8_t)get_user((uint8_t)from + i);
            }
            return true;
      }
      else
      {
            return false;
      }
}

/*** write **/
static bool
writeUserAccess(const void *to, int length, const void *from)
{
      if (to < PHYS_BASE && (to + length) < PHYS_BASE)
      {
            for (int i = 0; i < length; i++)
            {
                  if (put_user((uint8_t *)to + i, (uint8_t *)from + i) == -1)
                  {
                        return false;
                  }
            }
            return true;
      }
      else
      {
            return false;
      }
}

/** check if from is string or not **/
static bool
check_string(const void *from)
{
      if (from < PHYS_BASE)
      {
            char ch;
            int i = 0;
            while (ch != '\0')
            {
                  if ((from + i) >= PHYS_BASE)
                  {
                        return false;
                  }
                  if (get_user((uint8_t *)from + i) == -1)
                  {
                        return false;
                  }
                  ch = get_user((uint8_t *)from + i);
                  i++;
            }
            return true;
      }
      else
      {
            return false;
      }
}
