#include<iostream>
#include<cstring>
using namespace std;
const int size=4000100;
int ver[size],head[size],nxt[size];
bool vis[size];
int n,m,tot=0,ix,iy;
int a[2010][2010];
int dx[]={-1,0,1,0};
int dy[]={0,1,0,-1};
bool fl=false;
inline void add(int x,int y){
	ver[++tot]=y;
	nxt[tot]=head[x];
	head[x]=tot;
}
inline int enc(int x,int y){
	return (x-1)*m+y;
}
inline void addAdjBi(int x,int y,int xx_,int yy_){
	if(xx_<=0||xx_>=n+1||yy_<=0||yy_>=m+1) return;
	if(!a[xx_][yy_]) return;
	add(enc(x,y),enc(xx_,yy_));
	add(enc(xx_,yy_),enc(x,y));
}
void dfs(int x,int fa){
	vis[x]=true;
	for(int i=head[x];i;i=nxt[i]){
		int y=ver[i];
		if(!vis[y]) dfs(y,x);
		else if(y!=fa){
			fl=true;
			return;
		}
	}
}
int main(){
	ios::sync_with_stdio(0);
	while(1){
		cin>>n>>m;
		if(n==-1&&m==-1) return 0;
		memset(ver,0,sizeof(ver));
		memset(head,0,sizeof(head));
		memset(nxt,0,sizeof(nxt));
		memset(vis,false,sizeof(vis));
		memset(a,0,sizeof(a));
		fl=false;
		tot=0;
		for(int i=1;i<=n;i++){
			string s;
			cin>>s;
			int l=s.length();
			for(int j=0;j<l;j++){
				if(s[j]=='S'){
					ix=i,iy=j+1;
					a[ix][iy]=1;
				}
				else if(s[j]=='.'){
					a[i][j+1]=1;
				}
			}
		}
		for(int i=1;i<=n;i++) for(int j=1;j<=m;j++) if(a[i][j]) for(int k=0;k<4;k++) addAdjBi(i,j,i+dx[k],j+dy[k]);
		for(int i=1;i<=n;i++) if(a[i][1]&&a[i][m]) addAdjBi(i,1,i,m);
		for(int j=1;j<=m;j++) if(a[1][j]&&a[n][j]) addAdjBi(1,j,n,j);
		dfs(enc(ix,iy),-1);
		if(fl) cout<<"Yes\n";
		else cout<<"No\n";
	}
	return 0;
}
