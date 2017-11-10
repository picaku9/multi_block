#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct r_node // radix_tree node
{   
	char *key;
	int len;
	r_node *link;
	r_node *next;
	r_node(char* x, int n) : len(n), link(0), next(0)
	{
		key = new char[n+1];
		strncpy(key,x,n);
		key[n] = '\0';
	}
	~r_node() { delete[] key; }
} r_node;

int prefix(char* x, int n, char* key, int m);
r_node* find(r_node* t, char* x, int n=0);
void split(r_node* t, int k);
r_node* insert(r_node* t, char* x, int n=0);