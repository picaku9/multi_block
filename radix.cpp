#include <stdio.h>
#include <string.h>

typedef struct r_node // radix_tree  nodes 
{
    char *key;
    int len;
    r_node *link;
    r_node *next;
    r_node(char* x, int n) : len(n), link(0), next(0)
    {
        key = new char[n];
        strncpy(key,x,n);
    }
    ~r_node() { delete[] key; }
} r_node;

int prefix(char* x, int n, char* key, int m) // length of the biggest common prefix of x and key strings 
{
    for( int k=0; k<n; k++ )
        if( k==m || x[k]!=key[k] )
            return k;
    return n;
}

r_node* find(r_node* t, char* x, int n=0) // x key search in t tree 
{
    if( !n ) n = strlen(x)+1;
    if( !t ) return 0;
    int k = prefix(x,n,t->key,t->len);
    if( k==0 ) return find(t->next,x,n); // letâ<80><99>s look for the childâ<80><99>s node 
    if( k==n ) return t;
    if( k==t->len ) return find(t->link,x+k,n-k); // letâ<80><99>s look for at the childâ<80><99>s node 
    return 0;
}

void split(r_node* t, int k) // dividing t node according to k key symbol 
{
    r_node *p = new r_node(t->key+k,t->len-k);
    p->link = t->link;
    t->link = p;
    char* a = new char[k];
    strncpy(a,t->key,k);
    delete[] t->key;
    t->key = a;
    t->len = k;
}

r_node* insert(r_node* t, char* x, int n=0) // inserting x key in t tree 
{
    if( !n ) n = strlen(x)+1;
    if( !t ) return new r_node(x,n);
    int k = prefix(x,n,t->key,t->len);
    if( k==0 ) t->next = insert(t->next,x,n);
    else if( k<n )
    {
        if( k<t->len ) // cut or not to cut?
            split(t,k);
        t->link = insert(t->link,x+k,n-k);
    }
    return t;
}

int main() {
	FILE* fp;
	char* arg;
	r_node* root;
//	while(!feof(fp)){
		fp = fopen("top-1m.csv","r");
		fscanf(fp, "%*d,%s\n",arg);
		root = insert(root,arg);
//	}
	return 0;
}
