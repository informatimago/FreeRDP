
#include "../str.h"

#define check(expression, compare, expected, format) \
        check_internal(expression, compare, expected, format, result##__LINE__)
#define check_internal(expression, compare, expected, format, result) \
        {                                                                                       \
                typeof(expression) result = expression;                                         \
                if (!(result compare expected))                                                 \
                {                                                                               \
                        printf("%s:%d: Test %s,  %s %s %s failed!\n",                           \
                                __FILE__, __LINE__,__FUNCTION__,                                \
                                #expression, #compare, #expected);                              \
                        printf(" %s resulted in "format"\n", #expression,  result);             \
                        return FALSE;                                                           \
                }                                                                               \
        }



BOOL test_ref(struct string_funs * fun,  BYTE *string)
{
        check(fun->ref(string, 0), ==, 'h', "%d");
        check(fun->ref(string, 1), ==, 'e', "%d");
        check(fun->ref(string, 2), ==, 'l', "%d");
        check(fun->ref(string, 3), ==, 'l', "%d");
        check(fun->ref(string, 4), ==, 'o', "%d");
        check(fun->ref(string, 5), ==,  0,  "%d");
        return TRUE;
}

BOOL test_aref()
{
        BYTE string[] = "hello";
        return test_ref( & string_funs[0], string);
}

BOOL test_wref()
{
        WCHAR string[] = { 'h', 'e', 'l', 'l', 'o', 0 };
        return test_ref( & string_funs[1], (BYTE *)string);
}


BOOL test_set(struct string_funs * fun,  BYTE *string)
{
        fun->set(string, 2, 'w');
        check(fun->ref(string, 0), ==, 'h', "%d");
        check(fun->ref(string, 1), ==, 'e', "%d");
        check(fun->ref(string, 2), ==, 'w', "%d");
        check(fun->ref(string, 3), ==, 'l', "%d");
        check(fun->ref(string, 4), ==, 'o', "%d");
        check(fun->ref(string, 5), ==, 0, "%d");
        return TRUE;
}

BOOL test_aset()
{
        BYTE string[] = "hello";
        return test_ref( & string_funs[0], string);
}


BOOL test_wset()
{
        WCHAR string[] = { 'h', 'e', 'l', 'l', 'o', 0 };
        return test_ref( & string_funs[1], (BYTE *)string);
}


BOOL test_len(struct string_funs * fun,  BYTE *empty, BYTE *shortstr, BYTE *longstr)
{
        check(fun->len(empty), ==, 0, "%d");
        check(fun->len(shortstr), ==, 5, "%d");
        check(fun->len(longstr), ==, 27, "%d");
        return TRUE;
}

BOOL test_alen()
{
        BYTE empty[] = "";
        BYTE shortstr[] = "hello";
        BYTE longstr[] = "hello world! how do you do?";
        return test_len( & string_funs[0], empty, shortstr, longstr);
}


BOOL test_wlen()
{
        WCHAR empty[] = {0};
        WCHAR shortstr[] = { 'h', 'e', 'l', 'l', 'o', 0 };
        WCHAR longstr[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', ' ', 'h', 'o', 'w', ' ', 'd', 'o', ' ', 'y', 'o', 'u', ' ', 'd', 'o', '?', 0};
        return test_len( & string_funs[1], (BYTE *)empty,(BYTE *)shortstr, (BYTE *)longstr);
}

BOOL test_inc(struct string_funs * fun,  BYTE *string)
{
        BYTE * next = fun->inc(string, 0);
        check(next, ==, string, "%s");
        check(fun->ref(next, 0), ==, 'h', "%d");
        next = fun->inc(next, 6);
        check(fun->ref(next, 0), ==, 'w', "%d");
        next = fun->inc(next, 7);
        check(fun->ref(next, 0), ==, 'h', "%d");
        return TRUE;
}

BOOL test_ainc()
{
        BYTE string[] = "hello world! how do youwcompares do?";
        return test_inc( & string_funs[0], string);
}


BOOL test_winc()
{
        WCHAR string[] = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', ' ', 'h', 'o', 'w', ' ', 'd', 'o', ' ', 'y', 'o', 'u', ' ', 'd', 'o', '?', 0};
        return test_inc( & string_funs[1], (BYTE *)string);
}



#define countof(a)  (sizeof (a) / sizeof (a[0]))
#define no_convert(src, dst)      dst = (BYTE *)src
#define no_free(p)                (void)p
#define convert_to_utf8(src, dst) ConvertFromUnicode(CP_UTF8, 0, (WCHAR*)src, 0,(CHAR * *) &dst, 0, NULL, NULL)

static struct
{
        BYTE  astring[32];
        WCHAR wstring[32];
        struct
        {
                int expected;
                BYTE target[32];
        } tests[16];
} compares[] = {
        {
                "hello world",
                {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0},
                {
                        {1, ""},
                        {1, "h"},
                        {1, "hello worl"},
                        {0, "hello world"},
                        {-1, "hello world how do you do"},
                        {1, "hello aaaaa"},
                        {-1, "hello zzzzz"},
                        { -2, "done"}
                }
        },
        {
                "m",
                {'m', 0},
                {
                        {1, ""},
                        {1, "h"},
                        {1, "hh"},
                        {0, "m"},
                        {-1, "mm"},
                        {-1, "z"},
                        { -2, "done"}
                }
        },
        {
                "",
                {0},
                {
                        {0, ""},
                        {-1, "h"},
                        {-1, "hh"},
                        {-1, "m"},
                        {-1, "mm"},
                        {-1, "z"},
                        { -2, "done"}
                }
        }
};

BOOL test_compare()
{
        BOOL success = TRUE;
        int i;
        int j;
        struct string_funs * fun;

#define test_compare_loop(string, convert, free)                                                        \
        do                                                                                              \
        {                                                                                               \
                for (i = 0;i < countof(compares);i ++ )                                                 \
                {                                                                                       \
                        BYTE * string = (BYTE *)compares[i].string;                                     \
                        for(j = 0;compares[i].tests[j].expected != -2;j ++ )                            \
                        {                                                                               \
                                int expected = compares[i].tests[j].expected;                           \
                                BYTE * target =(BYTE *)compares[i].tests[j].target;                     \
                                int result = compare(fun, string, target);                              \
                                if (! (result == expected))                                             \
                                {                                                                       \
                                        BYTE *  cstr = 0;                                               \
                                        BYTE *  ctgt = 0;                                               \
                                        convert(string, cstr);                                          \
                                        convert(target, ctgt);                                          \
                                        printf("%s:%d: Test %s: compare(char, %s, %s) failed!\n",       \
                                                __FILE__, __LINE__, __FUNCTION__,                       \
                                                cstr, ctgt);                                            \
                                        printf(" it resulted in %d,  expected % d\n",                   \
                                                result, expected);                                      \
                                        free(cstr);                                                     \
                                        free(ctgt);                                                     \
                                        success = FALSE;                                                \
                                }                                                                       \
                        }                                                                               \
                }                                                                                       \
        }while(0)

        fun =  & string_funs[0];
        test_compare_loop(astring, no_convert,      no_free);

        fun =  & string_funs[1];
        test_compare_loop(wstring, convert_to_utf8, free);

        return success;
}



static struct
{
        BYTE  astring[32];
        WCHAR wstring[32];
        struct
        {
                int expected;
                BYTE target[32];
                int max;
        } tests[64];
} ncompares[] = {
        {
                "hello world",
                {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0},
                {
                        {1, "", 1000},
                        {1, "h", 1000},
                        {1, "hello worl", 1000},
                        {0, "hello world", 1000},
                        {-1, "hello world how do you do", 1000},
                        {1, "hello aaaaa", 1000},
                        {-1, "hello zzzzz", 1000},

                        {0, "", 0},
                        {0, "h", 0},
                        {0, "hello worl", 0},
                        {0, "hello world", 0},
                        {0, "hello world how do you do", 0},
                        {0, "hello aaaaa", 0},
                        {0, "hello zzzzz", 0},

                        {1, "", 5},
                        {1, "h", 5},
                        {0, "hello worl", 5},
                        {0, "hello world", 5},
                        {0, "hello world how do you do", 5},
                        {0, "hello aaaaa", 5},
                        {0, "hello zzzzz", 5},

                        {1, "", 8},
                        {1, "h", 8},
                        {0, "hello worl", 8},
                        {0, "hello world", 8},
                        {0, "hello world how do you do", 8},
                        {1, "hello aaaaa", 8},
                        {-1, "hello zzzzz", 8},

                        { -2, "done", 0}
                }
        },
        {
                "m",
                {'m', 0},
                {
                        {1, "", 1000},
                        {1, "h", 1000},
                        {1, "hh", 1000},
                        {0, "m", 1000},
                        {-1, "mm", 1000},
                        {-1, "z", 1000},

                        {1, "", 1},
                        {1, "h", 1},
                        {1, "hh", 1},
                        {0, "m", 1},
                        {0, "mm", 1},
                        {-1, "z", 1},

                        {1, "", 2},
                        {1, "h", 2},
                        {1, "hh", 2},
                        {0, "m", 2},
                        {-1, "mm", 2},
                        {-1, "z", 2},

                        { -2, "done", 0},
                }
        },
        {
                "",
                {0},
                {
                        {0, "", 1000},
                        {-1, "h", 1000},
                        {-1, "hh", 1000},
                        {-1, "m", 1000},
                        {-1, "mm", 1000},
                        {-1, "z", 1000},

                        {0, "", 0},
                        {0, "h", 0},
                        {0, "hh", 0},
                        {0, "m", 0},
                        {0, "mm", 0},
                        {0, "z", 0},

                        {0, "", 1},
                        {-1, "h", 1},
                        {-1, "hh", 1},
                        {-1, "m", 1},
                        {-1, "mm", 1},
                        {-1, "z", 1},

                        { -2, "done", 0}
                }
        }
};


BOOL test_ncompare()
{
        BOOL success = TRUE;
        int i;
        int j;
        struct string_funs * fun;

#define test_ncompare_loop(string, convert, free)                                                        \
        do                                                                                              \
        {                                                                                               \
                for (i = 0;i < countof(ncompares);i ++ )                                                \
                {                                                                                       \
                        BYTE * string = (BYTE *)ncompares[i].string;                                    \
                        for(j = 0;ncompares[i].tests[j].expected != -2;j ++ )                           \
                        {                                                                               \
                                int expected = ncompares[i].tests[j].expected;                          \
                                BYTE * target =(BYTE *)ncompares[i].tests[j].target;                    \
                                int max = ncompares[i].tests[j].max;                                    \
                                int result = ncompare(fun, string, target, max);                        \
                                if (! (result == expected))                                             \
                                {                                                                       \
                                        BYTE *  cstr = 0;                                               \
                                        BYTE *  ctgt = 0;                                               \
                                        convert(string, cstr);                                          \
                                        convert(target, ctgt);                                          \
                                        printf("%s:%d: Test %s: ncompare(char, %s, %s, %d) failed!\n",  \
                                                __FILE__, __LINE__, __FUNCTION__,                       \
                                                cstr, ctgt, max);                                       \
                                        printf(" it resulted in %d,  expected % d\n",                   \
                                                result, expected);                                      \
                                        free(cstr);                                                     \
                                        free(ctgt);                                                     \
                                        success = FALSE;                                                \
                                }                                                                       \
                        }                                                                               \
                }                                                                                       \
        }while(0)

        fun =  & string_funs[0];
        test_ncompare_loop(astring, no_convert,      no_free);

        fun =  & string_funs[1];
        test_ncompare_loop(wstring, convert_to_utf8, free);

        return success;
}

/* ncopy(str, destination, source, count) */
/*  */
/* str is the string_funs for the given string. */
/* destination is either a char or wide char string, same as source. */
/* source is either a char or wide char string. */
/*  */
/* ncopy copies exactly count characters  (char or wide char) from source */
/* to destination, including null characters if any, and beyond.  No null is added. */
/*  *\/ */
/* void ncopy(struct string_funs * str, BYTE * destination, BYTE * source, int count) */
/*  */
/*          */
/* /\**  */
/* contains(str, string, substring) */
/*  */
/* str is the string_funs for the given string. */
/* string is either a char or wide char string. */
/* substring is a char string. */
/*  */
/* Both strings are 0-terminated. */
/*  */
/* contains returns whether substring is a substring of string. */
/*  *\/   */
/* BOOL contains(struct string_funs * str, BYTE * string, char * substring); */
/*  */
/*  */
/*  */
/* /\**  */
/* LinkedList_StringHasSubstring(str, string, list) */
/*  */
/* str is the string_funs for the given string. */
/* string is either a char or wide char string. */
/* list is a wLinkedList of char strings. */
/*  */
/* All strings are 0-terminated. */
/*  */
/* LinkedList_StringHasSubstring returns whether at least one of the */
/* strings in the list is a substring of string. */
/*  *\/ */
/* BOOL LinkedList_StringHasSubstring(struct string_funs * str, BYTE * string, wLinkedList* list); */
/*  */
/*  */
/*  */
/*  */
/* /\**  */
/* mszFilterStrings(widechar, mszStrings, cchStrings, substrings) */
/*  */
/* widechar indicates whether mszStrings contains char strings or wide char strings. */
/* mszStrings is a double null-terminated list of strings,  either char or wide char,  according to widechar. */
/* cchString points to the total number of bytes used by mszStrings. */
/* substrings is a wLinkedList of char strings. */
/*  */
/* All strings are 0-terminated. */
/*  */
/* mszFilterStrings modifies mszStrings,  removing any string that contains one of the substrings. */
/* The total size pointed to by cchStrings is updated. */
/*  *\/ */
/* void mszFilterStrings(BOOL widechar, LPSTR mszStrings, DWORD * cchStrings, wLinkedList * substrings); */






int TestStr(int argc, char* argv[])
{
        BOOL success = TRUE;
        success &= test_aref();
        success &= test_wref();
        success &= test_aset();
        success &= test_wset();
        success &= test_alen();
        success &= test_wlen();
        success &= test_ainc();
        success &= test_winc();
        success &= test_compare();
        success &= test_ncompare();
        return success?0: -1;
}
