#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->vlimit;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

static pte_t *
findPte(pde_t *pgdir, const void *va)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
    return &pgtab[PTX(va)];
  }
  return 0;  
}

int
sys_mprotect(void) {
  void *addr;
  int len;
  if (argint(0, (int *)(&addr)) < 0 || argint(1, &len) < 0) {
    return -1;
  }

  if (addr != (void *)PGROUNDDOWN((uint)addr) || len <= 0) {
    return -1;
  }

  char *a, *last;
  pte_t *pte;

  pde_t* pgdir = myproc()->pgdir;

  a = (char*)addr;
  last = (char*)PGROUNDDOWN(((uint)addr) + len - 1);
  for(;;){
    if((pte = findPte(pgdir, a)) == 0)
      return -1; // not mapped
    if((*pte & PTE_P) == 0)
      return -1;
    *pte = *pte & (~PTE_W);
    if(a == last)
      break;
    a += PGSIZE;
  }
  lcr3(V2P(pgdir));
  return 0;
}

int
sys_munprotect(void) {
  void *addr;
  int len;
  if (argint(0, (int *)(&addr)) < 0 || argint(1, &len) < 0) {
    return -1;
  }
  if (addr != (void *)PGROUNDDOWN((uint)addr) || len <= 0) {
    return -1;
  }
  char *a, *last;
  pte_t *pte;

  pde_t* pgdir = myproc()->pgdir;

  a = (char*)addr;
  last = (char*)PGROUNDDOWN(((uint)addr) + len - 1);
  for(;;){
    if((pte = findPte(pgdir, a)) == 0)
      return -1;
    if((*pte & PTE_P) == 0)
      return -1; // not mapped
    *pte = *pte | (PTE_W);
    if(a == last)
      break;
    a += PGSIZE;
  }
  lcr3(V2P(pgdir));
  return 0;
}
