#include "parse_line.h"
#include "errorlog.h"

int line_byte_cnt(FILE *f)
{
        int	c;
        int 	i = 0;
        long 	p;   

        p = ftell(f);

        while ((c = fgetc(f)) != EOF) {
	    i++;
	    if (c == '\n')
		break;
        }
                
        if (fseek(f, p, SEEK_SET) != 0)
	    log_die("seek error reading config: %s\n", strerror(errno));
                        
        return i;
}

char * 
clean_line(char *s)
{	 
	rm_end_space(s);
	return rm_space(s);
}

void
rm_end_space(char *l)
{
	if (strncmp(&l[strlen(l) - 1], "\n", 1) == 0)
	    l[ strlen(l) - 1 ] = '\0';

	for (;;) {
	    if (isblank((int)l[strlen(l) - 1]) != 0)
		l[ strlen(l) - 1 ] = '\0';
	    else
		break;
	}
}

char *   
rm_space(char *s)
{
        while (isblank((int)s[0]) != 0)
            s++;

        return s;
}        

int 
check_line(char *l)
{
	char *ln = NULL;
	ln = clean_line(l);

        if (strncmp(ln, "#", 1) == 0 )
                return 1;

        if (strlen(ln) == 0)
                return 1;
        
        return 0;
}

int cnt_elements(const char * str, const char *d)
{
        int i, cnt = 1;

        for (i = 0; i < strlen(str); i++)
	    if (str[i] == *d && str[i+1] != '\0') /* CHECKS FOR TRAILING SEPERATOR */
		cnt++;
        return cnt;
}

int comp_string(const void *str1, const void *str2)
{
	const char **s1 = (const char **) str1;
	const char **s2 = (const char **) str2;	
        return strcmp(*s1, *s2);
}

void parse_string(const char *list, char **new_list, const char *d)
{
        char *e, *lptr;
        int i = 0;
        lptr = strdup(list);
 
        while((e = strsep(&lptr, d)) != NULL) {
                new_list[i++] = clean_line(e);
        }

	free(lptr);
}
