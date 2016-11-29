#include <common/Log.h>
#include <sys/time.h>
#include <cstdio>
#include <cstdlib>
#include <stdarg.h>
#include <cstring>
#include <ctype.h>
#include <pthread.h>


int g_log_level = LTRACE;
char g_log_path[512] = {0};
const char *log_level_str[6]={"TRACE","DEBUG","INFO","WARN","ERROR","DUMP",};
pthread_mutex_t log_mutex;


int LogInit(const char *log_file, int level)
{
	g_log_level=level;
	pthread_mutex_init(&log_mutex,NULL);
    if (log_file) snprintf(g_log_path, sizeof(g_log_path), "%s", log_file);
    else g_log_path[0] = '\0';
	return 0;
}

int LogDestroy()
{
	pthread_mutex_destroy(&log_mutex);
	return 0;
}

char* LogTime()
{
	static char sTime[32];
	time_t iCurrTime;
	struct tm stCurrTime;
	struct timeval ms;

	time(&iCurrTime);
	localtime_r(&iCurrTime, &stCurrTime);
	gettimeofday(&ms,NULL);
	sprintf(sTime, "%02d-%02d %02d:%02d:%02d:%03d",
		stCurrTime.tm_mon+1, stCurrTime.tm_mday,
		stCurrTime.tm_hour, stCurrTime.tm_min, stCurrTime.tm_sec, (int)ms.tv_usec/1000);

	return sTime;
}


int LogMsg(int curlevel,const char *sourceName,int sourceLine, const char *functionName, const char *szFormat, ...)
{
	va_list ap;
	FILE *fp = NULL;
    char functionName2[128] = {0};

    if (curlevel < g_log_level) return 0;


    strncpy(functionName2, functionName, 128);

    bool find_space = false;
    functionName = &functionName2[0];
    for(int i = strlen(functionName2) - 1; i >= 0; i--)
    {
        if (find_space)
        {
            if (functionName2[i] == ' ')
            {
                functionName = &functionName2[i+1];
                break;
            }
        }
        else
        {
            if (functionName2[i] == '(')
            {
                functionName2[i] = 0;
                find_space = true;
            }
        }
    }


    
	
    pthread_mutex_lock(&log_mutex);
    if (g_log_path[0] == '\0')
    {
        fp = stderr;
    }
    else if((fp = fopen(g_log_path, "a+")) == NULL)
    {
        fp = stderr;
        //iSize = ftell(fp);
        //if(iSize > 512 * 1048576)  //Log size no more than 500MB
        //{
        //    fclose(fp);
        //    pthread_mutex_unlock(&log_mutex);
        //    return 0;
        //}
    }
		
	fprintf(fp, "[%s][%s] [%s] ", LogTime(), log_level_str[curlevel], functionName);
	
	va_start(ap, szFormat);
	vfprintf(fp, szFormat, ap);
	va_end(ap);

	fprintf(fp, "\n");
    if (fp != stderr)
    {
	    fclose(fp);
    }
	
    pthread_mutex_unlock(&log_mutex);
	return 0;
}

