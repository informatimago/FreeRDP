/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * String utilities.
 *
 * Copyright 2018 Pascal J. Bourguignon <pjb@informatimago.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "str.h"

struct string_funs string_funs[2] = {{aref, aset, alen, ainc}, {wref, wset, wlen, winc}};

int aref(BYTE* string, int index)
{
	return string[index];
}

void aset(BYTE* string, int index, int character)
{
	string[index] = character;
}

int alen(BYTE* string)
{
	int length = 0;

	while (0 != aref(string, length))
	{
		length ++ ;
	}

	return length;
}

BYTE* ainc(BYTE* string, int increment)
{
	return string + increment;
}

int wref(BYTE* string, int index)
{
	return ((WCHAR*)string)[index];
}

void wset(BYTE* string, int index, int character)
{
	((WCHAR*)string)[index] = character;
}

int wlen(BYTE* string)
{
	int length = 0;

	while (0 != wref(string, length))
	{
		length ++ ;
	}

	return length;
}

BYTE* winc(BYTE* string, int increment)
{
	return string + 2 * increment;
}


int compare(struct string_funs* str, BYTE* string, BYTE* other_string)
{
	int i = 0;

	while (1)
	{
		if (str->ref(string, i) == 0)
		{
			return (other_string[i] == 0) ? 0 : -1;
		}

		if (other_string[i] == 0)
		{
			return 1;
		}

		if (str->ref(string, i) != other_string[i])
		{
			return (str->ref(string, i) <  other_string[i]) ? -1 : 1;
		}

		i ++ ;
	}
}

int ncompare(struct string_funs* str, BYTE* string, BYTE* other_string, int max)
{
	int i = 0;

	for (i = 0; i < max; i ++)
	{
		if (str->ref(string, i) == 0)
		{
			return (other_string[i] == 0) ? 0 : -1;
		}

		if (other_string[i] == 0)
		{
			return 1;
		}

		if (str->ref(string, i) != other_string[i])
		{
			return (str->ref(string, i) <  other_string[i]) ? -1 : 1;
		}
	}

	return 0;
}

BOOL contains(struct string_funs* str, BYTE* string, BYTE* substring)
{
	int wlen = str->len(string);
	int slen = strlen((char*)substring);
	int end = wlen - slen;
	int i = 0;

	for (i = 0; i <= end; i ++)
	{
		if (ncompare(str, str->inc(string, i), substring, slen) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}


void ncopy(struct string_funs* str, BYTE* destination, BYTE* source, int count)
{
	int i;

	for (i = 0; i < count; i ++)
	{
		str->set(destination, i, str->ref(source, i));
	}
}

BOOL LinkedList_StringHasSubstring(struct string_funs* str, BYTE* string, wLinkedList* list)
{
        LinkedList_Enumerator_Reset(list);
        while (LinkedList_Enumerator_MoveNext(list))
        {
                if (contains(str, string, LinkedList_Enumerator_Current(list)))
                {
                        return TRUE;
                }
        }
	return FALSE;
}

void mszFilterStrings(BOOL widechar, LPSTR mszReaders, DWORD* cchReaders, wLinkedList* substrings)
{
	struct string_funs* str = & string_funs[widechar ? 1 : 0];
	BYTE* current = (BYTE*)mszReaders;
	BYTE* destination = current;
	// int length = * cchReaders / (widechar?2:1);

	while (str->ref(current, 0))
	{
		int size = str->len(current) + 1;

		if (!LinkedList_StringHasSubstring(str, current, substrings))
		{
			/* Keep it */
			ncopy(str, destination, current, size);
			destination = str->inc(destination, size);
		}

		current = str->inc(current, size);
	}

	ncopy(str, destination, current, 1);
	* cchReaders = (BYTE*)destination - (BYTE*)mszReaders + 1;
}
