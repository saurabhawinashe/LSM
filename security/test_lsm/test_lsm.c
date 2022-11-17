#include <linux/lsm_hooks.h>
#include <linux/kern_levels.h>
#include <linux/binfmts.h>


char *sec_binaries[] = {"./dfa", "./sec_bin", "./new_dfa"};
int len = 3;

struct adj_node {
	char node[50];
	struct edge *head;
};

struct edge {
	char node[50];
	char transition[50];
	struct edge *next;
};

struct adj_node adj[1000];
int adj_index = 0; 

int curr_state = -1;
int graph_flag = 0;
int curr_pid = -1;

void add_node(char *node) {
	strcpy(adj[adj_index].node, node);
	adj[adj_index].head = NULL;
	adj_index++;
}


void add_edge(char *node1, char *node2, char *transition) {
	struct edge *new_edge = NULL;
	new_edge = (struct edge *)kmalloc(sizeof(struct edge), GFP_ATOMIC);
	strcpy(new_edge->node, node2);
	strcpy(new_edge->transition, transition);

	int head_ind = -1;
	for(int i=0;i<adj_index;i++) {
		//printk(KERN_ERR "%s\t %s\n", adj[i].node, node1);
		if(strcmp(adj[i].node, node1) == 0) {
			head_ind = i;
			break;
		}
	}
	//printk(KERN_ERR "HEADIND %d\n", head_ind);

	if(head_ind == -1)
		return;

	if(adj[head_ind].head==NULL) {
		adj[head_ind].head = new_edge;
		new_edge->next = NULL;
	}
	else {
		new_edge->next = adj[head_ind].head->next;
		adj[head_ind].head->next = new_edge;
	}
}

int create_adj_list(char *name) {
	struct file *file = NULL;
	file  = filp_open(name, O_RDWR, 0);
	if(IS_ERR(file))
		return 0;
	long long unsigned off = 0;
	int size=10;
	char line[100];
	
	while(1) {
		char ch='p';
		int index = 0;
		int valid=0, edge=0;
		while(ch!='\n') {
			size = kernel_read(file, &ch, 1, &off);
			if(size == 0)
				break;
			if(ch == ';')
				valid = 1;
			if(ch == '-')
				edge = 1;
			line[index++] = ch;
		}
		line[index++] = '\0';
		if(valid==1) {
			char comp[10];
			comp[0]='1';
			comp[1]='\0';

			if(edge==1) {
				int i=0, f=0;
				char node1[50], node2[50], trans[50];
				for(i=0;line[i]!=' ';i++)
					node1[i] = line[i];
				node1[i] = '\0';
				if(strcmp(comp, node1) == 0)
					continue;
				i+=4;
				for(;line[i]!=' ';i++) {
					//printk(KERN_ERR "hm %d\n", i);
					node2[f++] = line[i];
				}
				node2[f++] = '\0';
				
				//for(;line[i]!=',';i++);
				for(;line[i]!='=';i++);
				
				f=0;
				i++;
				for(;line[i]!=']';i++)
					trans[f++] = line[i];
				trans[f++] = '\0';
				//printk(KERN_ERR "Node 1 :  %s\t Node 2 : %s\t Trans : %s\n", node1, node2, trans);
				add_edge(node1, node2, trans);
			}
			else {
				char node[50];
				int i=0;
				for(i=0;line[i]!=';';i++)
					node[i] = line[i];
				node[i] = '\0';
				//printk(KERN_ERR "NODE %s\n", node);
				if(strcmp(comp, node) != 0)
					add_node(node);
			}
		}
		if(size == 0)
			break;
	}
	
	filp_close(file, NULL);
	return 0;
}



static int test_lsm_bprm_check_security(struct linux_binprm *bprm) {
	printk(KERN_ERR "Hello! Cool! %s\n", bprm->interp);
	return 0;
}

static int test_lsm_bprm_creds_for_exec(struct linux_binprm *bprm) {
	graph_flag = 0;
	printk(KERN_ERR "Hello from process init: %s\n", bprm->filename);
	int pos = -1;
	for(int i=0;i<len;i++) {
		if(strcmp(sec_binaries[i], bprm->filename) == 0) {
			pos = i;
			break;
		}
	}
	if(pos == -1) 
		return 0;
	char dot_name[20];
	int p;
	dot_name[0] = 'g';
	dot_name[1] = '/';
	for(p=2;bprm->filename[p]!='\0';p++) {
		dot_name[p] = bprm->filename[p];
	}
	dot_name[p++] = '.';
	dot_name[p++] = 'd';
	dot_name[p++] = 'o';
	dot_name[p++] = 't';
	dot_name[p++] = '\0';

	printk(KERN_ERR "%s\n", dot_name);

	int retval;
	retval = create_adj_list(dot_name);
	graph_flag = 1;
	curr_pid = current->pid;
	
	curr_state = 0;

	printk(KERN_ERR "%d\n", curr_state);

	return 0;
}

int make_transition(char *transition) {
	struct edge *head = adj[curr_state].head;
	if(head == NULL) {
		printk(KERN_ERR "hellll\n");
		return -1;
	}
	while(head) {
		if(strcmp(head->transition, transition) == 0) {
			for(int i=0;i<adj_index;i++) {
				if(strcmp(head->node, adj[i].node) == 0) {
					curr_state = i;
					if(strcmp(adj[curr_state].node, "E") == 0)
						return -1;
					return 0;
				}
			}
		}
		head = head->next;
	}
	return -1;

}

static int test_lsm_file_open(struct file *file) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "now syscall %d\n", current->latest_syscall);
	printk(KERN_ERR "Open is called\n");
	int status;
	status = make_transition("openat");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);	
	return status;
}

static int test_lsm_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode) {
	printk(KERN_ERR "mkdir called \n");
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	int status;
	status = make_transition("mkdir");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}

static int test_lsm_path_rmdir(const struct path *dir, struct dentry *dentry) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "rmdir called \n");
	int status;
	status = make_transition("rmdir");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}

static int test_lsm_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "tgkill called \n");
	int status;
	status = make_transition("tgkill");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}

static int test_lsm_inode_getattr(const struct path *path) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "fstat called \n");
	int status;
	status = make_transition("fstat");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}

static int test_lsm_path_rename(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "rename called \n");
	int status;
	status = make_transition("rename");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}

static int test_lsm_path_unlink(const struct path *dir, struct dentry *dentry) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "unlink called \n");
	int status;
	status = make_transition("unlink");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}


static int test_lsm_inode_permission(struct inode *inode, int mask) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "chdir called \n");
	int status;
	status = make_transition("chdir");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}


static int test_lsm_path_chmod(const struct path *path, umode_t mode) {
	if(graph_flag == 0 || curr_pid != current->pid)
		return 0;
	printk(KERN_ERR "chmod called \n");
	int status;
	status = make_transition("chmod");
	if(status != 0)
		printk(KERN_ERR "Error detected in flow\n");
	printk(KERN_ERR "STATE : %s\n", adj[curr_state].node);
	return status;
}



static struct security_hook_list test_lsm_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, test_lsm_bprm_check_security),
	LSM_HOOK_INIT(bprm_creds_for_exec, test_lsm_bprm_creds_for_exec),
	LSM_HOOK_INIT(file_open, test_lsm_file_open),
	LSM_HOOK_INIT(task_kill, test_lsm_task_kill),
	//LSM_HOOK_INIT(inode_getattr, test_lsm_inode_getattr),
	LSM_HOOK_INIT(path_rename, test_lsm_path_rename),
	LSM_HOOK_INIT(path_unlink, test_lsm_path_unlink),
	LSM_HOOK_INIT(path_rmdir, test_lsm_path_rmdir),
	//LSM_HOOK_INIT(inode_permission, test_lsm_inode_permission),
	LSM_HOOK_INIT(path_chmod, test_lsm_path_chmod),
	LSM_HOOK_INIT(path_mkdir, test_lsm_path_mkdir),
};


static int __init test_lsm_init(void) {
	printk(KERN_ERR "testlsm:We are doing things\n");
	security_add_hooks(test_lsm_hooks, ARRAY_SIZE(test_lsm_hooks), "test_lsm");
	return 0;
}

DEFINE_LSM(yama) = {
	.name = "test_lsm",
	.init = test_lsm_init,
};
	
