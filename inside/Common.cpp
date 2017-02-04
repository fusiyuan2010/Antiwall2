#include <inside/Common.h>

using namespace std;

#if defined(_MSC_VER) && _MSC_VER < 1900

int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap)
{
    int count = -1;

    if (size != 0)
        count = _vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
    if (count == -1)
        count = _vscprintf(format, ap);

    return count;
}

int c99_snprintf(char *outBuf, size_t size, const char *format, ...)
{
    int count;
    va_list ap;

    va_start(ap, format);
    count = c99_vsnprintf(outBuf, size, format, ap);
    va_end(ap);

    return count;
}

static int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime( &system_time );
    SystemTimeToFileTime( &system_time, &file_time );
    time =  ((uint64_t)file_time.dwLowDateTime )      ;
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
    tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
    return 0;
}

#else
#include <sys/time.h>
#endif


uint64_t get_current_time_ms() {
    struct timeval tm;
    gettimeofday(&tm, NULL);
    return (uint64_t)tm.tv_sec * 1000 + tm.tv_usec / 1000;
}

string g_username;
string g_password;
string g_proxyip;

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif


void GetLoginInfo() {
    char buf[255];
    g_username = "";
    g_password = "";
	g_proxyip = "";
    while(g_username == "") {
        printf("Username: ");
        scanf("%s", buf);
        g_username = buf;
    }

	while (g_proxyip == "") {
		printf("Remote IP: ");
		scanf("%s", buf);
		g_proxyip = buf;
	}
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    while(g_password == "") {
        printf("Password: ");
        scanf("%s", buf);
        g_password = buf;
    }
    SetConsoleMode(hStdin, mode);
#else
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    while(g_password == "") {
        printf("Password: ");
        scanf("%s", buf);
        g_password = buf;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
}

