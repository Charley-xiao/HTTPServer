#include<bits/stdc++.h>
using namespace std;
const int MAXN=1e5;
int n,m,test1=0,test2=0x7fffffff,ans;
struct door{
	string op;int t;
	inline void input(){cin>>op>>t;}
}a[MAXN+2];
int main(){
	ios::sync_with_stdio(0);
	cin>>n>>m;
	for(int i=1;i<=n;i++){
		a[i].input();
		if(a[i].op[0]=='A'){test1&=a[i].t;test2&=a[i].t;}
		else if(a[i].op[0]=='O'){test1|=a[i].t;test2|=a[i].t;}
		else if(a[i].op[0]=='X'){test1^=a[i].t;test2^=a[i].t;}
	}
	for(int i=30;i>=0;i--){
		if((test1>>i)&1) ans+=(1<<i);
		else if(((test2>>i)&1)&&(1<<i)<=m){ans+=(1<<i);m-=(1<<i);} 
	}
	cout<<ans<<endl;
	return 0;
}