#include<stdio.h>

int g[50][50] = {0};
int itr[50]={0};
int mitr[50] = {0};
int Messages[50][50];
int parent[50];
int capacity[50];

int max(int a, int b) {
	return a>b?a:b;
}
int election(int node, int par) {
	
	Messages[node][mitr[node]++] = par;
	printf("Recieved message ELECTION from %d at %d\n",par, node);
	if(mitr[node] == 1) {
		parent[node] = par;
	} else if(mitr[node] > 1) 
		return capacity[node];
	int best_cap = 0;
	for(int i=0; i<itr[node]; i++) {
		int u = g[node][i];
		if(u == par) continue;
		int cur_cap = election(u, node);
		best_cap = max(cur_cap, best_cap);
	}
	return best_cap;
}

int main() {
	int n, e, elec_node;
	printf("Enter number of nodes\n");
	scanf("%d",&n);
	printf("Enter capacity of each node:\n");
	for(int i = 0; i < n; i += 1) {
		scanf("%d",&capacity[i]);
	}
	printf("Node that starts election?\n");
	scanf("%d",&elec_node);
	
	printf("Enter number of Edges\n");
	scanf("%d",&e);
	for(int i = 0; i < e; i += 1) {
		int u, v;
		scanf("%d%d",&u, &v);
		g[u][itr[u]++] = v;
		g[v][itr[v]++] = u;
	}
	printf("Election Started at %d\n",elec_node);
	int best_cap = election(elec_node, -1);
	printf("Best capacity at election node recieved is %d\n",best_cap);
	return 0;
}

/*
INPUT:

10
4 6 2 4 3 1 8 2 4 5
0
12
0 1
0 3
1 2
3 2
1 4
2 5
2 6
4 9
5 9
5 8
7 8
6 7

*/
