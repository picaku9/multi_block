#include "radix.h"

int prefix(char* x, int n, char* key, int m) // length of the biggest common prefix of x and key strings 
{
    for( int k=0; k<n; k++ )
        if( k==m || x[k]!=key[k] )
            return k;
    return n;
}

r_node* find(r_node* t, char* x, int n) // x key search in t tree 
{
    if( !n ) n = strlen(x)+1;
    if( !t ) return 0;
    int k = prefix(x,n,t->key,t->len);
    if( k==0 ) return find(t->next,x,n); // look for the childs node (side)
    if( k==n ) return t;
    if( k==t->len ) return find(t->link,x+k,n-k); // look for at the child node (down)
    return 0;
}

void split(r_node* t, int k) // dividing t node according to k key symbol 
{
    r_node *p = new r_node(t->key+k,t->len-k);
    p->link = t->link;
    t->link = p;
	char* a = (char*)malloc((k + 1) * sizeof(char));
    strncpy(a, t->key, k);
	a[k] = '\0';
    delete[] t->key;
    t->key = a;
    t->len = k;
}

r_node* insert(r_node* t, char* x, int n) // inserting x key in t tree 
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