#include<bits/stdc++.h>

using namespace std;
vector<vector<int> > g(50);
vector<queue<string> > Messages(50);
int parent[50];
int capacity[50];

int election(int node, int par, string msg) {
	
	Messages[node].push(msg);
	cout<<"Recieved message "<<msg<<" at node "<<node<<endl;
	if(Messages[node].size() == 1) {
		parent[node] = par;
	} else if(Messages[node].size() > 1) 
		return capacity[node];
	int best_cap = 0;
	for(auto u: g[node]) {
		if(u == par) continue;
		int cur_cap = election(u, node, "ELECTION FROM " + to_string(node));
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
		g[u].push_back(v);
		g[v].push_back(u);
	}
	int best_cap = election(elec_node, -1, "ELECTION STARTED");
	cout<<"Best capacity at election node recieved is "<<best_cap<<endl;
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
