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

#ifndef str_h
#define str_h

#include <winpr/wtypes.h>
#include <winpr/collections.h>

/* 

We want to process strings and string lists that are stored in BYTE
arrays, either as char strings or as wide char strings.  To implement
functions that can work on either narrow or wide char strings,  we
will go thru a structure of primitives: 

    ref(string, index)->character
    len(string)->length
    inc(string, index)->string

string_funs[0] contains the functions for char strings, while
string_funs[1] contains the functions for wide char strings.

*/


int aref(BYTE * string, int index);
void aset(BYTE * string, int index, int character);
int alen(BYTE * string);
BYTE * ainc(BYTE * string, int increment);
int wref(BYTE * string, int index);
void wset(BYTE * string, int index, int character);
int wlen(BYTE * string);
BYTE * winc(BYTE * string, int increment);

struct string_funs
{
        int (*ref)(BYTE *, int);
        void (*set)(BYTE *, int, int);
        int (*len)(BYTE *);
        BYTE * (*inc)(BYTE *, int);
};

struct string_funs string_funs[2];


/** 
compare(str, string, other_string)

str is the string_funs for the given string.
string is either a char or wide char string.
other_string is a char string.

Both strings are 0-terminated.

compare returns -1,  0 or 1 depending on whether string is less,
equal or greater than other_string in lexical order.
 */  
int compare(struct string_funs * str, BYTE * string, BYTE * other_string);

 /** 
ncompare(str, string, other_string, max)

str is the string_funs for the given string.
string is either a char or wide char string.
other_string is a char string.
ringt
Both  strings are  0-terminated, however  the comparison  ends at  the
index max if the strings are longer.

ncompare  returns -1,  0 or  1 depending  on whether  string (or  it's
max-long prefix) is  less, equal or greater than  other_string (or its
max-long prefix) in lexical order.
 */  
int ncompare(struct string_funs * str, BYTE * string, BYTE * other_string, int max);

 /** 
ncopy(str, destination, source, count)

str is the string_funs for the given string.
destination is either a char or wide char string, same as source.
source is either a char or wide char string.

ncopy copies exactly count characters  (char or wide char) from source
to destination, including null characters if any, and beyond.  No null is added.
 */
void ncopy(struct string_funs * str, BYTE * destination, BYTE * source, int count);

        
/** 
contains(str, string, substring)

str is the string_funs for the given string.
string is either a char or wide char string.
substring is a char string.

Both strings are 0-terminated.

contains returns whether substring is a substring of string.
 */  
BOOL contains(struct string_funs * str, BYTE * string, BYTE * substring);



/** 
LinkedList_StringHasSubstring(str, string, list)

str is the string_funs for the given string.
string is either a char or wide char string.
list is a wLinkedList of char strings.

All strings are 0-terminated.

LinkedList_StringHasSubstring returns whether at least one of the
strings in the list is a substring of string.
 */
BOOL LinkedList_StringHasSubstring(struct string_funs * str, BYTE * string, wLinkedList* list);


/** 
mszFilterStrings(widechar, mszStrings, cchStrings, substrings)

widechar indicates whether mszStrings contains char strings or wide char strings.
mszStrings is a double null-terminated list of strings,  either char or wide char,  according to widechar.
cchString points to the total number of bytes used by mszStrings.
substrings is a wLinkedList of char strings.

All strings are 0-terminated.

mszFilterStrings modifies mszStrings,  removing any string that contains one of the substrings.
The total size pointed to by cchStrings is updated.
 */
void mszFilterStrings(BOOL widechar, LPSTR mszStrings, DWORD * cchStrings, wLinkedList * substrings);


#endif
