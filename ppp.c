typedef unsigned char u_char; 
typedef unsigned int u_int; 
typedef unsigned short u_short;

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "MD5.h"


struct ether_header

{

	u_int8_t ether_dhost[6];

	/* 以太网目的地址 */

	u_int8_t ether_shost[6];

	/* 源以太网地址 */

	 u_int16_t ether_type;

	/* 以太网类型 */


};

pcap_t *adhandle;

int time1;

char sk[]="m2o=crE54nyNUht[UxDROIG,6ZXu93lLAVjJbFes1;UnSxzUz3x.qVFiZg9aEVlv";

char g_userName[50],g_pwd[50];
    
int PPPoeDial(char *user,char *pwd,char *name,char *device);
    
void getSecondUserName(char *resultUserName,char* msg,char* username,char* pwd,int time1,int time2);
    
void getFirstUserName(char *userName,int time1);
    
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

pcap_if_t *d;
int j;
char wan[10], vth[10];
int valid = 1;

int main(int argc, char* argv[])
{
	pcap_if_t *alldevs;//接口结点指针

	

	/*int inum;
	int i=0;*/

	char errbuf[PCAP_ERRBUF_SIZE];
 
	/* 取得所有网卡列表*/
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s ", errbuf);
		return 1;
	}
 
	/* 输入列表*/
	/*for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s\n", ++i, d->name);
		if (d->description)
			printf(" (%s) \n", d->description);
		else
			printf(" (No description available) \n");
	}

	if(i==0)//如果网卡数等于0,则输出"找不到网卡"
	{
		printf(" No interfaces found! Make sure WinPcap is installed. \n");
		return -1;
	}*/

	/* 选择欲抓包网卡号*/
	/*printf("--------------选择要抓包的网卡！！！--------------\nEnter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
 
	if(inum < 1 || inum > i)
	{
		printf(" Interface number out of range. ");
		pcap_freealldevs(alldevs);
		return -1;
	}*/
	//复制命令行参数
	if(argc != 5){
	    printf("参数错误\nppp wanx vthx username password\n");
	    exit(0);
	}
	strcpy(vth, argv[1]);
	strcpy(wan, argv[2]);
	strcpy(g_userName, argv[3]);
	strcpy(g_pwd, argv[4]);


    for(d=alldevs; d&&strcmp(d->name,vth);d=d->next);//进行网卡选择
    if(!d)
        printf("找不到%s接口", vth);
    printf("找到%s\n", vth);
    sleep(8);
    printf("正在拨%s==>\n",d->name);

    /* 打开一个网卡进行抓包*/
    if ((adhandle= pcap_open_live(d->name, // 网卡名字
									      65536,   // 要捕获的数据包字节数 
									      1,    // 混杂模式为非0,非混杂为0
									      1,   // read timeout
									      errbuf   // error buffer
									      )) == NULL)
    {
	    fprintf(stderr," Unable to open the adapter. %s is not supported by WinPcap ", d->name);
	    pcap_freealldevs(alldevs);
	    return -1;
    }
    printf("正在监听%s...\n",d->name);

    char result[50];
    srand((unsigned int)time(NULL));
    time1=time(NULL);
    getFirstUserName(result,time1);
    printf("%s\n",result);
    PPPoeDial(result,g_pwd,wan,d->name);
    pcap_loop(adhandle,65535,packet_handler,NULL);
	return 0;
}

void getFirstUserName(char *userName,int time1)
{
	unsigned char username[100],psw[20];
	strcpy(username, g_userName);
	strcpy(psw, g_pwd);
	unsigned char strTime[9]={0};
	unsigned char first[200]={0};
	unsigned char md5Str[33]={0};
	unsigned char* pMd5Str=md5Str;
	unsigned char md5Result[16]={0};
	sprintf((char*)strTime,"%08x",time1);
	sprintf((char*)first,"%s%s%s%s",strTime,"m2o=crE54nyNUht[",username,psw);
	MD5_CTX md5;
	MD5Init(&md5);         		
	MD5Update(&md5,first,strlen((char*)first));
	MD5Final(&md5,md5Result);
	//把md5转换成字符串
	for(int j=0;j<16;j++)
	{
		sprintf((char*)pMd5Str,"%02x",md5Result[j]);
		pMd5Str+=2;
	}
	char md5Str19[20]={0};
	memcpy(md5Str19,md5Str,19);
	sprintf((char*)userName,"%s%s%s%s%s",strTime,"M","2021",md5Str19,username);
}

int PPPoeDial(char *user,char *pwd,char *name,char *device)
{
	char pppoe_cmd[1024];
	char ifname[40]="pppoe-";
	sprintf(pppoe_cmd,"/usr/sbin/pppd nodetach ipparam %s ifname %s nodefaultroute usepeerdns persist maxfail 1 user %s password %s ip-up-script /lib/netifd/ppp-up ipv6-up-script /lib/netifd/ppp-up ip-down-script /lib/netifd/ppp-down ipv6-down-script /lib/netifd/ppp-down mtu 1492 mru 1492 plugin rp-pppoe.so nic-%s &",\
	        name,strcat(ifname,name),user,pwd,device);
	system(pppoe_cmd);
	puts("拨号中。。。");
	return 1;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{    
	if(valid && pkt_data[22]==0x04&&pkt_data[23]==0x01)
	{
		pcap_breakloop(adhandle);
		valid = 0;
		char seed[10]={0};
		for(int i=0;i<8;i++)
		{
			sprintf(&seed[i],"%c",pkt_data[30+i]);
		}
		printf("seed:%s\n",seed);
		int time2=((unsigned int)rand())<<16|rand();
		char result[50]={0};
		getSecondUserName(result,seed,g_userName,g_pwd,time1,time2);
		printf("%s\n",result);
		sleep(8);
		PPPoeDial(result,g_pwd,wan,d->name);
	}
}

void getSecondUserName(char *resultUserName,char* msg,char* username,char* pwd,int time1,int time2)
{
	short* v7,*v8,*v9,*v10;//保存返回信息
	v7=(short*)&msg[6];
	v8=(short*)&msg[4];
	v9=(short*)&msg[2];
	v10=(short*)&msg[0];
	int v13=(*v10)%strlen(username);
	char code[100]={0},username2[100]={0},code2[100]={0},v45[30]={0},v41[100]={0},v37[100]={0};
	memcpy(code,sk,v13);
	memcpy(username2,username,v13);
	memcpy(code2,&sk[(*v9)%strlen(pwd)],63-(*v9)%strlen(pwd));
	memcpy(v45,pwd,(*v9)%strlen(pwd));
	memcpy(v41,&sk[(*v8)%(64-strlen(pwd))],63-(*v8)%(64-strlen(pwd)));
	memcpy(v37,&sk[(*v7)%(64-strlen(username))],63-(*v7)%(64-strlen(username)));
	time2^=time1;
	char tmp1[500]={0};
	unsigned char tmp2[500]={0},md5Result[100]={0};
	char timeStr[9]={0},timeStr2[9]={0};
	sprintf(timeStr,"%08x",time2);
	sprintf(timeStr2,"%08x",time2^time1);
	sprintf(tmp1,"%s%s%s%s%s%s%s",code,timeStr,username2,code2,v45,v41,v37);
	int v14=tmp1[11],v15=tmp1[3],v16=tmp1[2];
	char v57[100]={0},v53[100]={0},v49[100]={0},v46[100]={0};
	int v17=tmp1[0]%10+1;
	memcpy(v57,tmp1,v17);
	memcpy(v53,&tmp1[v16%5+1],v16%5+1);
	memcpy(v49,&tmp1[v15%7+1],v16%5+1);
	memcpy(v46,tmp1,v14%12+1);
	sprintf((char*)tmp2,"%s%s%s%s%s%s%s%s",v57,timeStr,v53,v46,v49,pwd,v41,v37);
	//printf("%s\n",tmp2);
	MD5_CTX md5;
	MD5Init(&md5);         		
	MD5Update(&md5,tmp2,strlen((char*)tmp2));
	MD5Final(&md5,md5Result);
	//把md5转换成字符串
	char tmp3[50];
	char *pMd5Str=tmp3;
	for(int j=0;j<16;j++)
	{
		sprintf((char*)pMd5Str,"%02x",md5Result[j]);
		pMd5Str+=2;
	}
	char tmp4[50]={0};
	memcpy(tmp4,tmp3,18);
	sprintf(resultUserName,"~ghca%sA2021%c%s%s",timeStr,timeStr2[0],tmp4,username);
	for(int i=5;i<strlen((char*)resultUserName);i++)
	{
		resultUserName[i]=toupper(resultUserName[i]);
	}
}

