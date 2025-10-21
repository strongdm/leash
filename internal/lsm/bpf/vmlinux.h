// Minimal vmlinux.h for LSM BPF programs
// This is a simplified version - normally you'd generate this with bpftool

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

// File mode type
typedef __u32 fmode_t;

// Sparse annotation for type checking
#define __force

// File mode constants
#define FMODE_READ		((__force fmode_t)0x1)
#define FMODE_WRITE		((__force fmode_t)0x2)
#define FMODE_EXEC		((__force fmode_t)0x20)

// File flags constants  
#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002

enum {
    false = 0,
    true = 1,
};

typedef long int __kernel_long_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef __kernel_ssize_t ssize_t;
typedef unsigned int __kernel_uid32_t;
typedef __kernel_uid32_t uid_t;
typedef unsigned int __kernel_gid32_t;
typedef __kernel_gid32_t gid_t;

struct qstr {
    union {
        struct {
            u32 hash;
            u32 len;
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

struct dentry {
    unsigned int d_flags;
    struct dentry *d_parent;
    struct qstr d_name;
    struct inode *d_inode;
    unsigned char d_iname[32];
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct file {
    struct path f_path;
    struct inode *f_inode;
    const struct file_operations *f_op;
    void *private_data;
    fmode_t f_mode;        // File mode (FMODE_READ, FMODE_WRITE, etc.)
    unsigned int f_flags;  // File flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
};

struct mm_struct;
struct vm_area_struct;

struct linux_binprm {
    struct vm_area_struct *vma;
    unsigned long vma_pages;
    struct mm_struct *mm;
    unsigned long p;
    unsigned int executable_stack;
    struct file *file;
    struct file *interpreter;
    char buf[256];
    char *filename;        // Path to executable
    int argc;              // Argument count  
    char **argv;           // Argument array
    int envc;              // Environment count
    char **envp;           // Environment array
};

// Network structures for socket_connect LSM hook
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};

struct in_addr {
    __u32 s_addr;
};

struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

struct sock {
    int sk_protocol;
    // Other fields omitted for simplicity
};

struct socket {
    struct sock *sk;
    // Other fields omitted for simplicity
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
