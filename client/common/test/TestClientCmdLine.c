#include <freerdp/client.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/settings.h>
#include <winpr/cmdline.h>
#include <winpr/spec.h>
#include <winpr/strlst.h>


static INLINE BOOL testcase(const char* name, char** argv, size_t argc,
                            int expected_return)
{
	int status;
	rdpSettings* settings = freerdp_settings_new(0);
	int i;
	printf("Running test:");

	for (i = 0; argv[i]; i ++)
	{
		printf(" %s", argv[i]);
	}

	printf("\n");

	if (!settings)
	{
		fprintf(stderr, "Test %s could not allocate settings!\n", name);
		fflush(stderr);
		return FALSE;
	}

	status = freerdp_client_settings_parse_command_line(settings, argc, argv, FALSE);
	freerdp_settings_free(settings);

	if (status != expected_return)
	{
		fprintf(stderr, "Test %s failed!\n", name);
		fprintf(stderr, "Expected status %d,  got status %d\n", expected_return, status);
		fflush(stderr);
		return FALSE;
	}

	return TRUE;
}

#if defined(_WIN32)
#define DRIVE_REDIRECT_PATH "c:\\Windows"
#else
#define DRIVE_REDIRECT_PATH "/tmp"
#endif

typedef struct
{
	int expected_status;
	const char* command_line[128];
	struct
	{
		int index;
		const char*   expected_value;
	} modified_arguments[8];
} test;

static test tests[] =
{
	{
		COMMAND_LINE_STATUS_PRINT_HELP,
		{"xfreerdp", "--help", 0},
		{{0}}
	},
	{
		COMMAND_LINE_STATUS_PRINT_HELP,
		{"xfreerdp", "/help", 0},
		{{0}}
	},
	{
		COMMAND_LINE_STATUS_PRINT_HELP,
		{"xfreerdp", "-help", 0},
		{{0}}
	},
	{
		COMMAND_LINE_STATUS_PRINT_VERSION,
		{"xfreerdp", "--version", 0},
		{{0}}
	},
	{
		COMMAND_LINE_STATUS_PRINT_VERSION,
		{"xfreerdp", "/version", 0},
		{{0}}
	},
	{
		COMMAND_LINE_STATUS_PRINT_VERSION,
		{"xfreerdp", "-version", 0},
		{{0}}
	},
	{
		0,
		{"xfreerdp", "test.freerdp.com", 0},
		{{0}}
	},
	{
		0,
		{"xfreerdp", "-v", "test.freerdp.com", 0},
		{{0}}
	},
	{
		0,
		{"xfreerdp", "--v", "test.freerdp.com", 0},
		{{0}}
	},
	{
		0,
		{"xfreerdp", "/v:test.freerdp.com", 0},
		{{0}}
	},
	{
		0,
		{"xfreerdp", "--plugin", "rdpsnd", "--plugin", "rdpdr", "--data", "disk:media:"DRIVE_REDIRECT_PATH, "--", "test.freerdp.com", 0},
		{{0}}
	},
	{
		0,
		{"xfreerdp", "/sound", "/drive:media,"DRIVE_REDIRECT_PATH, "/v:test.freerdp.com", 0},
		{{0}}
	},
	{
		0,
		{"xfreerdp", "-u", "test", "-p", "test", "test.freerdp.com", 0},
		{{4, "****"}, {0}}
	},
	{
		0,
		{"xfreerdp", "-u", "test", "-p", "test", "-v", "test.freerdp.com", 0},
		{{4, "****"}, {0}}
	},
	{
		0,
		{"xfreerdp", "/u:test", "/p:test", "/v:test.freerdp.com", 0},
		{{2, "/p:****"}, {0}}
	},
	{
		COMMAND_LINE_ERROR_NO_KEYWORD,
		{"xfreerdp", "-invalid", 0},
		{{0}}
	},
	{
		COMMAND_LINE_ERROR_NO_KEYWORD,
		{"xfreerdp", "--invalid", 0},
		{{0}}
	},
	{
		COMMAND_LINE_STATUS_PRINT,
		{"xfreerdp", "/kbd-list", 0},
		{{0}}
	},
	{
		COMMAND_LINE_STATUS_PRINT,
		{"xfreerdp", "/monitor-list", 0},
		{{0}}
	},
	{
		COMMAND_LINE_ERROR,
		{"xfreerdp", "/sound", "/drive:media:"DRIVE_REDIRECT_PATH, "/v:test.freerdp.com", 0},
		{{0}}
	},
	{
		COMMAND_LINE_ERROR,
		{"xfreerdp", "/sound", "/drive:media,/foo/bar/blabla", "/v:test.freerdp.com", 0},
		{{0}}
	},
#if 0
	{
		COMMAND_LINE_STATUS_PRINT,
		{"xfreerdp", "-z", "--plugin", "cliprdr", "--plugin", "rdpsnd", "--data", "alsa", "latency:100", "--", "--plugin", "rdpdr", "--data", "disk:w7share:/home/w7share", "--", "--plugin", "drdynvc", "--data", "tsmf:decoder:gstreamer", "--", "-u", "test", "host.example.com", 0},
		{{0}}
	},
#endif
};


void check_modified_arguments(test* test, char** command_line, int* rc)
{
	int k;
	const char*   expected_argument;

	for (k = 0; (expected_argument = test->modified_arguments[k].expected_value); k ++)
	{
		int index = test->modified_arguments[k].index;
		char* actual_argument = command_line[index];

		if (0 != strcmp(actual_argument, expected_argument))
		{
			fprintf(stderr, "Failure: overridden argument %d is %s but it should be %s\n",
			        index, actual_argument, expected_argument);
			fflush(stderr);
			* rc = -1;
		}
	}
}

int TestClientCmdLine(int argc, char* argv[])
{
	int rc = 0;
	int i;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i ++)
	{
		int failure = 0;
		char** command_line = string_list_copy(tests[i].command_line);

		if (!testcase(__FUNCTION__,
		              command_line, string_list_length((const char * const*)command_line),
		              tests[i].expected_status))
		{
			fprintf(stderr, "Failure parsing arguments.\n");
			failure = 1;
		}

		check_modified_arguments(& tests[i], command_line, & failure);

		if (failure)
		{
			string_list_print(stdout, command_line);
			rc = -1;
		}

		string_list_free(command_line);
	}

	return rc;
}

