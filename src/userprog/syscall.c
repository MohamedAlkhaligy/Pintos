#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "pagedir.h"
#include <console.h>
#include <string.h>
#include <stdio.h>

#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

#include "filesys/filesys.h"
#include "filesys/file.h"

#define DEBUG false
#define DEBUGF false

static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static bool check_string(const void *from);
static bool writeUserAccess(const void *to, int length, const void *from);
static bool readUserAccess(const void *from, int length, const void *to);

struct file_descriptor *get_file_descriptor(struct thread *t, size_t fd);
static bool check_validation_boundry(char *add, int length);
static bool check_valid_fd(int fd);

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
            int status = (int *)f->esp + 1 >= PHYS_BASE ? -1 : *((int *)f->esp + 1);
            exit(status);
            break;
      }
      case SYS_EXEC:
      {
            char *cmd_line = *((char **)f->esp + 1);
            f->eax = exec(cmd_line);
            break;
      }
      case SYS_WAIT:
      {
            pid_t child_id = *((pid_t *)f->esp + 1);
            f->eax = wait(child_id);
            break;
      }
      case SYS_CREATE:
      {
            char *name = *((char **)f->esp + 1);
            unsigned size = *((unsigned *)f->esp + 2);
            f->eax = create(name, size);
            break;
      }

      case SYS_REMOVE:
      {
            char *name = *((char **)f->esp + 1);
            f->eax = remove(name);
            break;
      }
      case SYS_OPEN:
      {
            char *name = *((char **)f->esp + 1);
            f->eax = open(name);
            break;
      }
      case SYS_FILESIZE:
      {
            int fd = *((int *)f->esp + 1);
            f->eax = filesize(fd);

            break;
      }
      case SYS_READ:
      {
            int fd = *((int *)f->esp + 1);
            void *buffer = (void *)(*((int *)f->esp + 2));
            unsigned size = *((unsigned *)f->esp + 3);
            f->eax = read(fd, buffer, size);
            break;
      }
      case SYS_WRITE:
      {
            int fd = *((int *)f->esp + 1);
            void *buffer = (void *)(*((int *)f->esp + 2));
            unsigned size = *((unsigned *)f->esp + 3);
            f->eax = write(fd, buffer, size);
            break;
      }
      case SYS_SEEK:
      {
            int fd = *((int *)f->esp + 1);
            int position = *((int *)f->esp + 2);
            seek(fd, position);
            break;
      }
      case SYS_TELL:
      {
            int fd = *((int *)f->esp + 1);
            f->eax = tell(fd);
            break;
      }
      case SYS_CLOSE:
      {
            int fd = *((int *)f->esp + 1);
            close(fd);
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
            lock_acquire(&file_lock);
            pid_t child_id = process_execute(cmd_line);
            lock_release(&file_lock);
            thread_current()->exec_proc = true;
            sema_down(&thread_current()->child_loaded);
            thread_current()->exec_proc = false;
            return thread_current()->loaded == true ? child_id : -1;
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

/* Creates a new file called file initially initial size bytes in size. Returns true if successful,
   false otherwise. Creating a new file does not open it: opening the new file is
   a separate operation which would require a open system call*/

bool create(const char *file, unsigned initial_size)
{
      int result = false;
      if (file != NULL && check_validation_boundry(file, strlen(file)) && initial_size >= 0)
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

/* Deletes the file called file. Returns true if successful, false otherwise. A file may be
   removed regardless of whether it is open or closed, and removing an open file does
   not close it*/
bool remove(const char *file)
{
      int result = false;
      if (file != NULL && check_validation_boundry(file, strlen(file)))
      {
            lock_acquire(&file_lock);
            result = filesys_remove(file);
            lock_release(&file_lock);
      }
      else
      {
            exit(-1);
      }
      return result;
}
/* Opens the file called file. Returns a nonnegative integer handle called a 
   “file descriptor” (fd), or -1 if the file could not be opened*/
int open(const char *file)
{
      int result = false;
      if (file != NULL && check_validation_boundry(file, strlen(file)))
      {
            struct file *open_file;
            size_t new_fd;

            lock_acquire(&file_lock);
            open_file = filesys_open(file);
            if (open_file != NULL)
            {
                  result = true;
                  new_fd = get_fd(thread_current());
            }
            lock_release(&file_lock);
            if (result)
            {
                  struct file_descriptor *fd_file = malloc(sizeof(struct file_descriptor));
                  fd_file->_file = open_file;
                  fd_file->fd = new_fd;
                  list_push_back(&thread_current()->files, &fd_file->fd_elem);
                  return fd_file->fd;
            }
            else
            {
                  return -1;
            }
      }
      else
      {
            exit(-1);
      }
}

/* Returns the size, in bytes, of the file open as fd. */
int filesize(int fd)
{
      if (check_valid_fd(fd))
      {
            struct file_descriptor *fd_file = get_file_descriptor(thread_current(), fd);
            if (fd_file != NULL)
            {
                  int res;
                  lock_acquire(&file_lock);
                  res = file_length(fd_file->_file);
                  lock_release(&file_lock);
                  return res;
            }
      }
      return -1;
}

/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition 
other than end of file). Fd 0 reads from the keyboard using input_getc().
*/
int read(int fd, void *buffer, unsigned size)
{
      if(!check_validation_boundry(buffer,size)){
            exit(-1);
      }
      if(fd == 1){//stdout 
            return -1;
      }
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
      else
      {
            if (check_valid_fd(fd) && size >= 0)
            {
                  struct file_descriptor *fd_file = get_file_descriptor(thread_current(), fd);
                  if (fd_file != NULL)
                  {
                        int res;
                        lock_acquire(&file_lock);
                        res = file_read(fd_file->_file, buffer, size);
                        lock_release(&file_lock);
                        return res;
                  }
            }
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
      if(!check_validation_boundry(buffer,size)){
            exit(-1);
      }
      if(fd == 0){ //stdin 
            return 0;
      }
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
      else
      {
            if (check_valid_fd(fd) && size >= 0 )
            {
                  struct file_descriptor *fd_file = get_file_descriptor(thread_current(), fd);
                  if (fd_file != NULL)
                  {
                        int res;
                        lock_acquire(&file_lock);
                        res = file_write(fd_file->_file, buffer, size);
                        lock_release(&file_lock);
                        return res;
                  }
            }
      }
      return -1;
}
/* Changes the next byte to be read or written in open file fd to position, expressed in
   bytes from the beginning of the file. (Thus, a position of 0 is the file’s start.)*/
void seek(int fd, unsigned position)
{
      if (check_valid_fd(fd) && position >= 0)
      {
            struct file_descriptor *fd_file = get_file_descriptor(thread_current(), fd);
            if (fd_file != NULL)
            {
                  int res;
                  lock_acquire(&file_lock);
                  file_seek(fd_file->_file, position);
                  lock_release(&file_lock);
            }
      }
}
/*Returns the position of the next byte to be read or written in open file fd, expressed
  in bytes from the beginning of the file.*/
unsigned tell(int fd)
{
      if (check_valid_fd(fd))
      {
            struct file_descriptor *fd_file = get_file_descriptor(thread_current(), fd);
            if (fd_file != NULL)
            {
                  unsigned res;
                  lock_acquire(&file_lock);
                  res = file_tell(fd_file->_file);
                  lock_release(&file_lock);
                  return res;
            }
      }
      return 0;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open
   file descriptors, as if by calling this function for each one.*/
void close(int fd)
{
      if (fd == 0 || fd == 1)
      {
            exit(-1);
      }
      if (check_valid_fd(fd))
      {
            struct file_descriptor *fd_file = get_file_descriptor(thread_current(), fd);
            if (fd_file != NULL)
            {
                  
                  lock_acquire(&file_lock);
                  file_close(fd_file->_file);
                  lock_release(&file_lock);
                  list_remove(&fd_file->fd_elem);
                  
            }
      }
}

static bool check_validation_boundry(char *add, int length)
{

      if (is_user_vaddr(add) && is_user_vaddr(add + length) && add > PHYS_BOUND && (add + length) >PHYS_BOUND)
      {
            return true;
      }
      return false;
}

struct file_descriptor *get_file_descriptor(struct thread *t, size_t fd)
{
      struct list *children = &thread_current()->files;
      for (struct list_elem *e = list_begin(children); e != list_end(children);
           e = list_next(e))
      {
            struct file_descriptor *f = list_entry(e, struct file_descriptor, fd_elem);
            if (f != NULL && f->fd == fd)
            {
                  if (DEBUG)
                        printf("##thread %p , id : %d is the child to wait\n", f, f->fd);
                  return f;
            }
      }
      return NULL;
}

static bool check_valid_fd(int fd)
{
      return !((fd < 2) || (fd >= thread_current()->fd_counter));
}

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
      for (int i = 0; i < length; i++)
      {
            if (get_user((uint8_t *)from + i) == -1)
            {
                  return false;
            }
            if (DEBUG)
                  printf("from %p\n", (uint8_t *)from + i);
            *((uint8_t *)to + i) = (uint8_t)get_user((uint8_t *)from + i);
      }
}

/*** write **/
static bool
writeUserAccess(const void *to, int length, const void *from)
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

/** check if from is string or not **/
static bool
check_string(const void *from)
{

      char ch;
      int i = 0;
      while (ch != '\0')
      {
            if (get_user((uint8_t *)from + i) == -1)
            {
                  return false;
            }
            ch = get_user((uint8_t *)from + i);
            i++;
      }
      return true;
}
