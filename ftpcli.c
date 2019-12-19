/*****************************************
 * 文 件 名: ftpcli.c
 * 功能描述：FTP传递接口
 * 作    者: 
 * 完成日期: 
 * 修改记录：
 * 日    期:
 * 修 改 人:
 * 说    明: 1) get_remote_file_by_ftp
 *              从远端下载文件到本地的方法
 *           2) put_remote_file_by_ftp
 *              上传本地文件到远端的方法
 *****************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <setjmp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include "pubf_eod_file.h"

static int ftp_cmd(int sockfd, char *checkno, char *resp, char *pcmd, ...);
static void replacechar(char *str, char a, char b);
static int ftp_connect_port(int sockfd);
static int recvdata(int datafd, FILE *fp, int mode);
static int recvstreamdata(int datafd, char **buf, int mode);
static int senddata(int datafd, FILE *fp, int mode);
static int ftp_get_file(int sockfd, char *localfpath, char *remotefpath);
static int ftp_put_file(int sockfd, char *localfpath, char *remotefpath);
static int get_dest_file_list(int sockfd, char *path, char *head, char **buf);
static int check_resp_num(int sockfd, const char *num, char *resp);
static int add_ftp_cmd_end_symbol(char *src);
static void mysleep(long usec);
static int ftp_connect_pasv(int sockfd);
static size_t readn(int fd, void *vptr, size_t n);
static size_t writen(int fd, const void *vptr, size_t n);


int get_remote_files_lst_by_ftp(FTPRQST_S *rqst, char *resp)
{
	struct sockaddr_in servaddr;
	int sockfd;
	int iret = -1;
/*	
	add_ftp_cmd_end_symbol(rqst->user);	
	add_ftp_cmd_end_symbol(rqst->passwd);	
	add_ftp_cmd_end_symbol(rqst->remotefpath);
*/	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("get sock error");
		return -1;
	}
	
	servaddr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, rqst->ip, &servaddr.sin_addr))
	{
		sprintf(resp, "address is not valid");
		goto FAILED;
	}
	servaddr.sin_port = htons(rqst->port);
	
	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("connect error");
		sprintf(resp, "connect error");
		goto FAILED;
	}
	
	/* check connect result: 220 */
	if (check_resp_num(sockfd, "220", NULL) == -1)
		goto FAILED;
	
	/* check login user: 331 passwd: 230 */
	if (ftp_cmd(sockfd, "331", NULL, "USER %s\r\n", rqst->user) == -1)
		goto FAILED;
	if (ftp_cmd(sockfd, "230", NULL, "PASS %s\r\n", rqst->passwd) == -1)
		goto FAILED;
	
	/* CMD: TYPE AS */
	if (ftp_cmd(sockfd, "200", NULL, "TYPE A\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}
	if (ftp_cmd(sockfd, "350", NULL, "REST 0\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}

	iret = get_dest_file_list(sockfd, rqst->mfile.remotehomepath,
						rqst->mfile.filehead, &rqst->mfile.filelist);
	if (iret != 0)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}

	ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
	close(sockfd);
	return 0;
FAILED:
	close(sockfd);
	return iret;
}


int get_remote_file_by_ftp(FTPRQST_S *rqst, char *resp)
{
	struct sockaddr_in servaddr;
	int sockfd;
	int iret = -1;
/*	
	add_ftp_cmd_end_symbol(rqst->user);	
	add_ftp_cmd_end_symbol(rqst->passwd);	
	add_ftp_cmd_end_symbol(rqst->remotefpath);
*/
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("get sock error");
		return -1;
	}
	
	servaddr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, rqst->ip, &servaddr.sin_addr))
	{
		sprintf(resp, "address is not valid");
		goto FAILED;
	}
	servaddr.sin_port = htons(rqst->port);
	
	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("connect error");
		sprintf(resp, "connect error");
		goto FAILED;
	}
	
	/* check connect result: 220 */
	if (check_resp_num(sockfd, "220", NULL) == -1)
		goto FAILED;
	
	/* check login user: 331 passwd: 230 */
	if (ftp_cmd(sockfd, "331", NULL, "USER %s\r\n", rqst->user) == -1)
		goto FAILED;
	if (ftp_cmd(sockfd, "230", NULL, "PASS %s\r\n", rqst->passwd) == -1)
		goto FAILED;
	
	/* CMD: TYPE A */
	if (ftp_cmd(sockfd, "200", NULL, "TYPE A\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}
	
	if (ftp_cmd(sockfd, "350", NULL, "REST 0\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}
	
	iret = ftp_get_file(sockfd, rqst->localfpath, rqst->remotefpath);
	if (iret != 0)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}

	ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
	close(sockfd);
	return 0;
FAILED:
	close(sockfd);
	return iret;
}

int mget_remote_files_by_ftp(FTPRQST_S *rqst, char *resp)
{
	struct sockaddr_in servaddr;
	int sockfd;
	int iret = -1;
	char cmd[ 128 ];
	char fname[ 128 ];
	char *strp = NULL;
	char *sbegin = NULL;
	int len = 0;
	int count = 0;

/*	
	add_ftp_cmd_end_symbol(rqst->user);	
	add_ftp_cmd_end_symbol(rqst->passwd);	
	add_ftp_cmd_end_symbol(rqst->remotefpath);
*/
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("get sock error");
		return -1;
	}
	
	servaddr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, rqst->ip, &servaddr.sin_addr))
	{
		sprintf(resp, "address is not valid");
		goto FAILED;
	}
	servaddr.sin_port = htons(rqst->port);
	
	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("connect error");
		sprintf(resp, "connect error");
		goto FAILED;
	}
	
	/* check connect result: 220 */
	if (check_resp_num(sockfd, "220", NULL) == -1)
		goto FAILED;
	
	/* check login user: 331 passwd: 230 */
	if (ftp_cmd(sockfd, "331", NULL, "USER %s\r\n", rqst->user) == -1)
		goto FAILED;
	if (ftp_cmd(sockfd, "230", NULL, "PASS %s\r\n", rqst->passwd) == -1)
		goto FAILED;
	
	/* CMD: TYPE A */
	if (ftp_cmd(sockfd, "200", NULL, "TYPE A\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}
	
	if (ftp_cmd(sockfd, "350", NULL, "REST 0\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}

	memset(cmd, '\0', sizeof(cmd));
	sprintf(cmd, "CWD %s\r\n", rqst->mfile.remotehomepath);
	if (ftp_cmd(sockfd, "250", NULL, cmd) == -1)
		return -1;

	chdir(rqst->mfile.localhomepath);

	strp = rqst->mfile.filelist;
	sbegin = rqst->mfile.filelist;
	while (*strp != '\0')
	{
		if ((*strp == '\r') && (*(strp + 1) == '\n'))
		{
			memset(fname, '\0', sizeof(fname));
			strncpy(fname, sbegin, len);

			iret = ftp_get_file(sockfd, fname, fname);
			if (iret != 0)
			{
				ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
				goto FAILED;
			}
			count++;
			len = 0;
			strp += 2;
			sbegin = strp;
			continue;
		}
		len++;
		strp++;
	}
	rqst->mfile.count = count;
	ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
	close(sockfd);
	return 0;
FAILED:
	close(sockfd);
	return iret;
}


int mput_remote_files_by_ftp(FTPRQST_S *rqst, char *resp)
{
	struct sockaddr_in servaddr;
	int sockfd;
	int iret = -1;
	char cmd[ 128 ];
	char fname[ 128 ];
	char *strp = NULL;
	char *sbegin = NULL;
	int len = 0;
	int count = 0;
/*	
	add_ftp_cmd_end_symbol(rqst->user);	
	add_ftp_cmd_end_symbol(rqst->passwd);	
	add_ftp_cmd_end_symbol(rqst->remotefpath);	
*/

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("get sock error");
		return -1;
	}
	
	servaddr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, rqst->ip, &servaddr.sin_addr))
	{
		sprintf(resp, "address is not valid");
		goto FAILED;
	}
	servaddr.sin_port = htons(rqst->port);
	
	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("connect error");
		sprintf(resp, "connect error");
		goto FAILED;
	}

	
	/* check connect result: 220 */
	if (check_resp_num(sockfd, "220", NULL) == -1)
		goto FAILED;
	
	/* check login user: 331 passwd: 230 */
	if (ftp_cmd(sockfd, "331", NULL, "USER %s\r\n", rqst->user) == -1)
		goto FAILED;
	if (ftp_cmd(sockfd, "230", NULL, "PASS %s\r\n", rqst->passwd) == -1)
		goto FAILED;
	
	/* CMD: TYPE A */
	if (ftp_cmd(sockfd, "200", NULL, "TYPE A\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}
	
	if (ftp_cmd(sockfd, "350", NULL, "REST 0A\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}

	memset(cmd, '\0', sizeof(cmd));
	sprintf(cmd, "CWD %s\r\n", rqst->mfile.remotehomepath);

	if (ftp_cmd(sockfd, "250", NULL, cmd) == -1)
		return -1;
	chdir(rqst->mfile.localhomepath);

	strp = rqst->mfile.filelist;
	sbegin = rqst->mfile.filelist;
	while (*strp != '\0')
	{
		if ((*strp == '\r') && (*(strp + 1) == '\n'))
		{
			memset(fname, '\0', sizeof(fname));
			strncpy(fname, sbegin, len);

			iret = ftp_put_file(sockfd, fname, fname);
			if (iret != 0)
			{
				ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
				goto FAILED;
			}
			count++;
			len = 0;
			strp += 2;
			sbegin = strp;
			continue;
		}
		len++;
		strp++;
	}
	rqst->mfile.count = count;

	ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
	close(sockfd);
	return 0;
FAILED:
	close(sockfd);
	return iret;
}

int put_remote_file_by_ftp(FTPRQST_S *rqst, char *resp)
{
	struct sockaddr_in servaddr;
	int sockfd;
	int iret = -1;
/*	
	add_ftp_cmd_end_symbol(rqst->user);	
	add_ftp_cmd_end_symbol(rqst->passwd);	
	add_ftp_cmd_end_symbol(rqst->remotefpath);	
*/

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("get sock error");
		return -1;
	}
	
	servaddr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, rqst->ip, &servaddr.sin_addr))
	{
		sprintf(resp, "address is not valid");
		goto FAILED;
	}
	servaddr.sin_port = htons(rqst->port);
	
	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		perror("connect error");
		sprintf(resp, "connect error");
		goto FAILED;
	}

	
	/* check connect result: 220 */
	if (check_resp_num(sockfd, "220", NULL) == -1)
		goto FAILED;
	
	/* check login user: 331 passwd: 230 */
	if (ftp_cmd(sockfd, "331", NULL, "USER %s\r\n", rqst->user) == -1)
		goto FAILED;
	if (ftp_cmd(sockfd, "230", NULL, "PASS %s\r\n", rqst->passwd) == -1)
		goto FAILED;
	
	/* CMD: TYPE A */
	if (ftp_cmd(sockfd, "200", NULL, "TYPE A\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}
	
	if (ftp_cmd(sockfd, "350", NULL, "REST 0A\r\n") == -1)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}

	iret = ftp_put_file(sockfd, rqst->localfpath, rqst->remotefpath);
	if (0 != iret)
	{
		ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
		goto FAILED;
	}

	ftp_cmd(sockfd, "221", NULL, "QUIT\r\n");
	close(sockfd);
	return 0;
FAILED:
	close(sockfd);
	return iret;
}


void mget_mput_free(FTPRQST_S *rqst)
{
	if (rqst->mfile.filelist != NULL)
	{
		free(rqst->mfile.filelist);
		rqst->mfile.filelist = NULL;
	}
}

static int ftp_cmd(int sockfd, char *checkno, char *resp, char *pcmd, ...)
{
	
	FILE *fp;
	va_list ap;
	char buf[256];
	char *str;
	char sret[4];

	fp = fdopen(sockfd, "w");
	va_start(ap, pcmd);
	/* send command */
	vfprintf(fp, pcmd, ap);
	fflush(fp);
	va_end(ap);
	
AGAIN:
	memset(buf, '\0', 256);
	str = buf;
	while (1)
	{
		if (read(sockfd, str, 1) < 0)
		{
			perror("read error");
			return -1;
		}
		if (*str == '\n')
			break;
		str++;
	}

	str = buf;

	while (*str == ' ')
		str++;

	if ((str[3] != ' ') || (str[3] == '-'))
		goto AGAIN;

	if (NULL != resp)
		strcpy(resp, str);
	if (strncmp(str, checkno, 3) == 0)
	{
		return 0;
	}
	else
	{	strncpy(sret, str, 3);
		return atoi(sret);
	} 
}

static void replacechar(char *str,char a,char b)
{
	char *p;
	while ((p=strchr(str,a)))
	{
		*p=b;
	}
}

static int ftp_connect_port(int sockfd)
{
	int listener, port;
	socklen_t addr_len;
	struct sockaddr_in addr;
	char localaddr[32] = {0};
	char buf[256] = {0};
	int iret = 0;
	int on = 1;
	int len = sizeof(&on);
	char response[ 256 ] = {0};
	
	time_t t;

	addr_len = sizeof(addr);
	if (getsockname(sockfd, (struct sockaddr *)&addr, &addr_len) < 0)
	{
		perror("getsockname error");
		return -1;
	}
	else
	{
		inet_ntop(AF_INET, &addr.sin_addr, localaddr, sizeof(localaddr));
		replacechar(localaddr, '.', ',');
	}

	listener = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, len);
	srand((unsigned)time(&t));
	addr.sin_port = htons(LOCAL_FILE_TRANSFER_PORT + rand()%1000);

	if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)))
	{
	    close(listener);
	    return -1;	
	}
	
	if (listen(listener, 5))
	{
	    close(listener);
	    return -1;	
	}

	addr_len = sizeof(addr);
	if ( getsockname(listener, (struct sockaddr *)&addr, &addr_len)<0 )
	{
		perror("getsockname error");
		return -1;
	}

	port = ntohs(addr.sin_port);

	sprintf(buf, "PORT %s,%d,%d\r\n", localaddr, port/256, port%256);

	iret = ftp_cmd(sockfd, "200", NULL, buf);
	if ((iret >= 100) && (iret <= 300))
	{
		while (check_resp_num(sockfd, "200", response) != 0);
	}
	else if ((iret == -1) || (iret > 300))
	{
		return -1;
	}
/*
printf("BEGIN accept!\n");
	datafd = accept(listener, NULL, NULL);
	if (datafd < 0)
	{
		close(listener);
		return -1;
	}
printf("END accept!\n");
*/

	return listener;
}

static int recvdata(int datafd, FILE *fp, int mode)
{
	int recvfd;
/*
	socklen_t addr_len;
	struct sockaddr_in tranaddr;
*/
	char buf[2048] = {0};
	size_t n;
	int fd;

	/*addr_len = sizeof(tranaddr);*/
	memset(buf, '\0', sizeof(buf));
/*
	if ((recvfd = accept(datafd, (struct sockaddr *)&tranaddr, &addr_len)) <0)
	{
		perror("accept error");
		return -1;
	}
*/
	if (mode == 2)
	{
		recvfd = accept(datafd, NULL, NULL);
		close(datafd);
	}
	else
		recvfd = datafd;

	fd = fileno(fp);
	while((n = readn(recvfd, buf, sizeof(buf))) > 0)
	{
		/*fwrite(buf, n, 1, fp);*/
		write(fd, buf, n);
		memset(buf, 0, sizeof(buf));
	}

	close(recvfd);

	return 0;
}

static int recvstreamdata(int datafd, char **buf, int mode)
{
	int recvfd;
	char *strp = NULL;
	char *ptmp = NULL;
	char bufTmp[ 17 ];
	size_t n = 0, len = 0;

	memset(bufTmp, '\0', sizeof(bufTmp));
	if (mode == 2)
	{
		recvfd = accept(datafd, NULL, NULL);
		close(datafd);
	}
	else
		recvfd = datafd;

	while((n = readn(recvfd, bufTmp, 16)) > 0)
	{
		ptmp = (char*)realloc(strp, (16 + len) * sizeof(char));
		if (!ptmp)
		{
			free(strp);
			return -1;
		}
		strp = ptmp;
		memcpy(strp + len, bufTmp, 16);
		len = len + n;
		n = 0;
		memset(bufTmp, '\0', sizeof(bufTmp));
	}
	*buf = strp;
	close(recvfd);

	return 0;
}


static int senddata(int datafd, FILE *fp, int mode)
{
/*
	int sendfd;
	socklen_t addr_len;
	struct sockaddr_in tranaddr;
*/
	char buf[2048] = {0};
	size_t n;
	int sendfd;

/*
	addr_len = sizeof(tranaddr);
	sendfd = accept(datafd, (struct sockaddr *)&tranaddr, &addr_len);
*/
	if (mode == 2)
	{
		sendfd = accept(datafd, NULL, NULL);
		close(datafd);
	}
	else
		sendfd = datafd;


	/* BIN方式 */
	while((n = read(fileno(fp), buf, sizeof(buf))) > 0)
	{
		writen(sendfd, buf, n);
		memset(buf, '\0', sizeof(buf));
	}
	
	close(sendfd);
	return 0;
}

static int ftp_get_file(int sockfd, char *localfpath, char *remotefpath)
{

	int transfd;
	FILE *fp;
	int iret = 0;
	int mode; /* 1: PASV   2:PORT */
	char response[ 256 ] = {0};

	if ((fp = fopen(localfpath, "w")) == NULL)
	{
		perror("open file error");
		return -1;
	}

	if ((transfd = ftp_connect_pasv(sockfd)) == -1)
	{
		transfd = ftp_connect_port(sockfd);
		if (transfd == -1)
		{
			remove(localfpath);
			fclose(fp);
			return -1;
		}
		mode = 2;
	}
	else
		mode = 1;
	
	iret = ftp_cmd(sockfd, "150", NULL, "RETR %s\r\n", remotefpath);
	if (iret == 0)
	{
		recvdata(transfd, fp, mode);
		if (check_resp_num(sockfd, "226", NULL) == -1)
		{
			remove(localfpath);
			fclose(fp);
			close(transfd);
			return -1;	
		}
	}
	else 	if ((iret >= 100) && (iret <= 300))
	{
		while (check_resp_num(sockfd, "150", response) != 0);
		recvdata(transfd, fp, mode);
		if (check_resp_num(sockfd, "226", NULL) == -1)
		{
			remove(localfpath);
			fclose(fp);
			close(transfd);
			return -1;	
		}
	} 
	else
	{
		remove(localfpath);
		fclose(fp);
		close(transfd);
		return iret;
	}

	/*close(transfd);*/
	fclose(fp);
	return 0;
}

static int ftp_put_file(int sockfd, char *localfpath, char *remotefpath)
{
	int transfd;
	int iret = 0;
	FILE *fp;
	int mode; /* 1: PASV   2:PORT */

	if ((fp = fopen(localfpath, "r")) == NULL)

	{
		perror("open file error");
		return -1;
	}
/*
	if ((transfd = ftp_connect_port(sockfd)) == -1)
	{
		transfd = ftp_connect_pasv(sockfd);
		printf("[%d]transfd=[%d]\n", __LINE__, transfd);
		if (transfd == -1)
		{
			fclose(fp);
			return -1;
		}
		mode = 1;
	}
	else
		mode = 2;
*/
	if ((transfd = ftp_connect_pasv(sockfd)) == -1)
	{
		transfd = ftp_connect_port(sockfd);
		if (transfd == -1)
		{
			remove(localfpath);
			fclose(fp);
			return -1;
		}
		mode = 2;
	}
	else
		mode = 1;

	iret = ftp_cmd(sockfd, "150", NULL, "STOR %s\r\n", remotefpath);
	
	if (iret == 0)
	{
		senddata(transfd, fp, mode);
		if (check_resp_num(sockfd, "226", NULL) == -1)
		{
			fclose(fp);
			close(transfd);
			return -1;	
		}
	}
	else 	if ((iret >= 100) && (iret <= 300))
	{
		while (check_resp_num(sockfd, "150", NULL) != 0);
		senddata(transfd, fp, mode);
		if (check_resp_num(sockfd, "226", NULL) == -1)
		{
			fclose(fp);
			close(transfd);
			return -1;	
		}
	}
	else
	{
		close(transfd);
		fclose(fp);
		return iret;
	}
	
	/*close(transfd);*/
	fclose(fp);
	return 0;
}

static int get_dest_file_list(int sockfd, char *path, char *head, char **buf)
{
	int transfd;
	int iret = 0;
	char cmd[ 1024 ];
	int mode;

	sprintf(cmd, "CWD %s\r\n", path);
	if (ftp_cmd(sockfd, "250", NULL, cmd) == -1)
		return -1;
	
	if ((transfd = ftp_connect_pasv(sockfd)) == -1)
	{
		transfd = ftp_connect_port(sockfd);
		if (transfd == -1)
		{
			return -1;
		}
		mode = 2;
	}
	else
		mode = 1;

	if (NULL != head)
		sprintf(cmd, "NLST %s*\r\n", head);
	else
		sprintf(cmd, "NLST .\r\n");

	iret = ftp_cmd(sockfd, "150", NULL, cmd);
	if (iret == 0)
	{
		recvstreamdata(transfd, buf, mode);
		if (check_resp_num(sockfd, "226", NULL) == -1)
		{
			close(transfd);
			return -1;	
		}
	}
	else
	{
		return iret;
	}

	return 0;
}

static int check_resp_num(int sockfd, const char *num, char *resp)
{
	char buf[ 256 ];
	char *strp = buf;
	
	memset(buf, '\0', sizeof(buf));
	
	while (1)
	{
		if (readn(sockfd, strp, 1) < 0)
		{
			perror("read error");
			return -1;
		}
		if (*strp == '\n')
			break;
		strp++;
	}
	strp = buf;
	
	while (*strp == ' ')
		strp++;

	if (resp != NULL)
	{
		memset(resp, '\0', 256);
		strcpy(resp, strp);
	}
	
	if (strncmp(strp, num, 3) == 0)
		return 0;
	else
		return -1;
}

static int add_ftp_cmd_end_symbol(char *src)
{
	int len = 0;
	if (src == NULL)
		return -1;
	
	len = strlen(src);
	*(src + len) = '\r';
	*(src + len + 1) = '\n';
	*(src + len + 2) = '\0';
	
	return 0;
}


static void mysleep(long usec)
{
	struct timeval timeout;
	timeout.tv_sec = usec / 1000000;
	timeout.tv_usec = usec - 1000000 * timeout.tv_sec;
	select(1, NULL, NULL, NULL, &timeout);
}

static int ftp_connect_pasv(int sockfd)
{
	char cmd[ 128 ];
	char response[ 256 ] = {0};
	int h1, h2, h3, h4, p1, p2;
	char *start;
	unsigned short ftp_dtp_port;
	struct in_addr ftp_dtp_addr;
	struct sockaddr_in sa;
	int sock;
	int iret;

	sprintf(cmd, "PASV\r\n");
	iret = ftp_cmd(sockfd, "227", response, cmd);
	if ((iret >= 100) && (iret <= 300))
	{
		while (check_resp_num(sockfd, "227", response) != 0);
	}
	else if ((iret == -1) || (iret > 300))
		return -1;
	
	start = strchr(response, '(');
	if (sscanf(++start, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2 ) < 6)
		return -1;
	ftp_dtp_port = (p1<<8) | p2;
	ftp_dtp_addr.s_addr = htonl( (h1<<24) | (h2<<16) | (h3<<8) | h4 );
	
	if((sock = socket(AF_INET, SOCK_STREAM, 0) ) < 0)
		return -1;
	/* Connect the socket */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(ftp_dtp_port);
	sa.sin_addr = ftp_dtp_addr;
	if(connect(sock, (struct sockaddr *) &sa, sizeof(struct sockaddr_in)) < 0)
		return -1;
	return sock;
}

static size_t readn(int fd, void *vptr, size_t n)
{
	size_t  nleft;
	size_t nread;
	char *ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0)
	{
		if ((nread = read(fd, ptr, nleft)) < 0)
		{
			if (errno == EINTR)
				nread = 0;
			else
				return(-1);
		}
		else if (nread == 0)
			break;	/* EOF */

		nleft -= nread;
		ptr += nread;
	}
	return(n - nleft);
}

static size_t writen(int fd, const void *vptr, size_t n)
{
        size_t          nleft;
        size_t         nwritten;
        const char      *ptr;

        ptr = vptr;
        nleft = n;
        while (nleft > 0)
        {
                if ((nwritten = write(fd, ptr, nleft)) <= 0)
                {
                        if (errno == EINTR)
                                nwritten = 0;
                        else
                                return(-1);                     /* error */
                }

                nleft -= nwritten;
                ptr   += nwritten;
        }
        return(n);
}
