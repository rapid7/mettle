/**
 * strtok, wordexp and other standard functions either do not handle quotes
 * properly, are non-portable, or simply do not work in all embedded scenarios.
 *
 * Based on argv parser found here:
 * https://stackoverflow.com/questions/9659697/parse-string-into-array-based-on-spaces-or-double-quotes-strings
 */

#include <ctype.h>
#include <stdlib.h>

char ** argv_split(char *args, char **argv, size_t *argc)
{
	char *p, *start_of_word = NULL;
	int c;
	enum states { DULL, IN_WORD, IN_STRING, IN_STRING_LIT } state = DULL;

	for (p = args; *p != '\0'; p++) {
		c = (unsigned char) *p;
		switch (state) {
		case DULL:
			if (isspace(c)) {
				continue;
			}

			if (c == '"') {
				state = IN_STRING;
				start_of_word = p + 1;
				continue;
			}
			if (c == '\'') {
				state = IN_STRING_LIT;
				start_of_word = p + 1;
				continue;
			}
			state = IN_WORD;
			start_of_word = p;
			continue;

		case IN_STRING:
			if (c == '"') {
				*p = 0;
				argv = realloc(argv, sizeof(char *) * (*argc + 1));
				argv[(*argc)++] = start_of_word;
				state = DULL;
			}
			continue;

		case IN_STRING_LIT:
			if (c == '\'') {
				*p = 0;
				argv = realloc(argv, sizeof(char *) * (*argc + 1));
				argv[(*argc)++] = start_of_word;
				state = DULL;
			}
			continue;

		case IN_WORD:
			if (isspace(c)) {
				*p = 0;
				argv = realloc(argv, sizeof(char *) * (*argc + 1));
				argv[(*argc)++] = start_of_word;
				state = DULL;
			}
			continue;
		}
	}

	if (state != DULL) {
		argv = realloc(argv, sizeof(char *) * (*argc + 1));
		argv[(*argc)++] = start_of_word;
	}

	argv = realloc(argv, sizeof(char *) * (*argc + 2));
	argv[(*argc)] = NULL;

	return argv;
}
