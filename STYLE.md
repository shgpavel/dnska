# C Style Guide

This is my style guide for C projects. The main guiding principles are:

1. The style should be easy for a human to learn and write by hand. It shouldn't
   be necessary to rely on linting tools to write correct code once you get used
   to it.
2. Prioritize readability over shortcuts that save a few keystrokes.
3. Prefer style choices which can be justified by objective reasoning over
   aesthetics. However, aesthetics are an acceptable justification if objective
   rationale does not exist.

This guide aims to be more exhaustive and specific than is always necessary - in
general if you skim this guide and then try to match the style of nearby code,
you'll be okay.

The style guidelines are presented with [RFC
2199](https://www.ietf.org/rfc/rfc2119.txt) style language, using the keywords
SHOULD, MUST, etc, to indicate required levels of compliance.

Send questions and feedback to
[~sircmpwn/public-inbox@lists.sr.ht](https://lists.sr.ht/~sircmpwn/public-inbox).

**Table of contents**

- [Editor basics](#editor-basics)
- [Features to use](#features-to-use)
- [Features to avoid](#features-to-avoid)
- [Brace placement](#brace-placement)
- [Comments](#comments)
- [Function declarations](#function-declarations)
- [goto](#goto)
- [Header files](#header-files)
- [Space placement](#space-placement)
- [Splitting long lines](#splitting-long-lines)
- [Struct and union declarations](#struct-and-union-declarations)
- [Variable declarations](#variable-declarations)
- [Variable and function naming](#variable-and-function-naming)

## Editor basics

**[.editorconfig](https://editorconfig.org/)**

```
root = true

[*.{c,h}]
end_of_line = lf
insert_final_newline = true
charset = utf-8
trim_trailing_whitespace = true
indent_style = tab
indent_size = 8
max_line_length = 80
```

Place this file at `.editorconfig` in the root of your project to automatically
apply these rules to your editor.

Programmers **MUST indent with 8-column tabs, instead of spaces.**

- 8 column tabs are the default, and will render consistently in your editor,
  your terminal, web browsers, and other places where your code may appear.
- Tabs are more usable than spaces for programmers with accessibility
  requirements. (Note: this alone should end the discussion immediately for C
  and all other languages).
- Makefiles require tabs; using them for code as well is more consistent.

Programmers **SHOULD hard wrap lines to 80 columns.**

- Wrapping at 80 columns discourages excessive nesting and overlong lines,
  especially when combined with 8-column-wide indentation.
- You may have a high-resolution screen, but many of your collaborators don't,
  or use tiling window managers to subdivide their workspace, or are reading
  patches in their email client, etc. Wrapping lines is common courtesy.
- Occasional 81 or 82 column lines may be overlooked when the code would be
  worse off for splitting them up.

See [splitting long lines](#splitting-long-lines) for specific advice on
splitting up long declarations, expressions, and so on.

## Features to use

Programmers **MUST use const to constrain their pointer usage.**

- When borrowing pointers, use const if possible.

Programmers **MUST use the most appropriate integer types for their situation.**

- Include `stdint.h` to use integers with a specified storage size.
- Use `uintmax_t` and `intmax_t` to store any integer.
- Use `size_t` for array indicies, the value of sizeof, and so on.
- `limits.h` includes constants for the maximum and minimum bounds of many
  types, use it to assert your assumptions or declare arrays (e.g. `PATH_MAX`).

Programmers **MUST use enums over #define or magic constants.**

- Declare flags with bitwise arithmetic:

  ```c
  enum my_enum {
      MY_ENUM_FLAG_A = 1 << 0,
      MY_ENUM_FLAG_B = 1 << 1,
      MY_ENUM_FLAG_C = 1 << 2,
  };
  ```

  For easier copy/paste.

Programmers **SHOULD use assert to enforce their assumptions.**

- If you expect a pointer to be non-null, assert it. If you expect an integer to
  be within certain bounds, assert it. If you expect a buffer to be of a certain
  size, assert it.
- Use asserts for programmer errors, not normal runtime errors. If an assertion
  ever fails, the resolution is always to update the code.
- Assertions must not have side-effects. The following example is incorrect:

  ```c
  assert(write(...) >= 0);
  ```

Programmers **SHOULD prefer to stack-allocate resources.**

- It cleans itself up!
- You MAY pass pointers to your stack resources to functions, but you MUST
  ensure that those pointers do not outlive their stack frame.

Programmers **SHOULD prefer calloc for heap-allocated resources.**

- It automatically zeroes out the memory so you can't forget to.

## Features to avoid

Programmers **SHOULD NOT use language extensions**, such as gcc-specific features.

- These make your code non-portable between compilers. Additionally, it makes
  your code non-portable between *parsers*, which has implications for linters,
  code analysis, and so on.
- See the [C11 specification][c11-spec] if in doubt, or whichever specification
  is appropriate for your target language revision.

[c11-spec]: http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf

Programmers **MUST use preprocessor tests before using language extensions.**

- Test for gcc, clang, etc, before using a C language extension that is required
  for your code to work correctly (for example, alignment attributes). Use
  an `#error` branch if no portable option exists.

Programmers **MUST NOT use libc extensions**, such as glibc-specific features.

- These make your code non-portable between systems. glibc is not universal, and
  in fact is only found on Linux systems (and Hurd, but if you think Hurd is
  relevant then you damn well ought to support BSD).
- BSD systems also include many non-portable utilities. On the surface these
  may seem reasonable, but include a shim for other platforms if you choose to
  use them. You probably should not use them.
- The [POSIX specification](https://pubs.opengroup.org/onlinepubs/9699919799/)
  is a useful reference for portable stdlib functions. You may have these
  installed on-site as `man 3p funcname`.
- Do not define `_GNU_SOURCE` or `_DEFAULT_SOURCE`, instead use
  `_POSIX_C_SOURCE` or `_XOPEN_SOURCE`. See
  [feature-test-macros(7)][feature-test-macros].

[feature-test-macros]: http://man7.org/linux/man-pages/man7/feature_test_macros.7.html

Programmers **MUST NOT use wide characters.**

- All strings must be treated as UTF-8.

Programmers **SHOULD NOT use inline functions.**

- Your linker knows better than you how to optimize your code.
- At best, this is a premature optimization.

Programmers **SHOULD NOT use macros.**

- Macros introduce additional complexity by being able to break out of the call
  frame sandbox, accessing locals and changing your code's behavior in
  unpredictable ways.
- C has a second-class macro system, making them difficult to write and
  difficult to debug. Hacks like extra parenthesis around everything,
  backslashes to continue on multiple lines, useless loops and branches to
  introduce scopes - all make your code more difficult to read and understand.
- Macros are opaque - their behavior is not inferable from code which invokes
  them. Example: which of these are macros, and which are function calls?

  ```c
  begin(ctx);
  do_work(ctx);
  send_notification(ctx);
  end(ctx);
  ```

  Spoiler: you can't tell.

Programmers **SHOULD NOT use typedef.**

- Using typedefs to hide pointers or avoid typing the word "struct" makes the
  code more opaque in exchange for ergonomics/aesthetics, which is not an
  acceptable tradeoff. The storage class and semantics of pointers and structs
  require special attention and therefore should be obvious from the type.
- The exception is for function pointer types, see [type
  declarations](#type-declarations).

Programmers **SHOULD NOT use pointer arithmetic.**

- Pointer arithmetic is to be avoided as a general rule.
- Sometimes it's necessary to use pointer arithmetic, for example to convert the
  return value of `strstr` to an index.

Programmers **SHOULD NOT use global variables.**

- Prefer to allocate them at the highest appropriate call frame and pass
  pointers around.

## Brace placement

Programmers **MUST use braces where the language makes them optional.**

Single-line if statements, loops, etc, must use braces. It's a small loss for
ergonomics with a tangible benefit for error prevention.

Programmers **MUST place opening braces on the same line.**

Correct:

```c
if (cond) {
    /* ... */
}

if (cond) {
    /* ... */
} else if (other cond) {
    /* ... */
} else {
    /* ... */
}

for (...) {
    /* ... */
}

while (...) {
    /* ... */
}

do {
    /* ... */
} while (...);
```

Incorrect:

```c
if (cond)
{
    /* ... */
}

if (cond)
{
    /* ... */
}
else if (other cond)
{
    /* ... */
}
else
{
    /* ... */
}

for (...)
{
    /* ... */
}

while (...)
{
    /* ... */
}

do
{
    /* ... */
}
while (...);
```

Programmers **MUST place opening braces on the next line for function declarations.**

Correct:

```c
static int
my_function(parameters...)
{
        /* function body */
}
```

Incorrect:

```c
static int
my_function(parameters...) {
        /* function body */
}
```

- Functions are more important than other kinds of declarations, and attention
  should be called to that.
- We already split this line for reasons explained in [function
  declarations](#function-declarations) and this looks better.

Programmers **MUST align case branches with the switch statement.**

Correct:

```c
switch (...) {
case FOOBAR:
        /* ... */
        break;
case FOOBAZ:
        /* ... */
        break;
default:
        /* ... */
        break;
}
```

Incorrect:

```c
switch (...) {
    case FOOBAR:
            /* ... */
            break;
    case FOOBAZ:
            /* ... */
            break;
    default:
            /* ... */
            break;
}
```

Programmers **MUST use "fallthrough" comments.**

Example:

```c
switch (...) {
case FOOBAR:
        /* ... */
        /* fallthrough */
case FOOBAZ:
        /* ... */
        break;
default:
        /* ... */
        break;
}
```

This is not necessary when several "case" statements follow the same branch:

```c
switch (...) {
case FOOBAR:
case FOOBAZ:
        /* ... */
        break;
default:
        /* ... */
        break;
}
```

## Comments

For single line or inline comments, programmers **MUST** use `/* */`:

Correct:

```c
/* Coordinates: */
int x = 0; /* x coordinate of foobar */
int y = 0; /* y coordinate of foobar */
```

Incorrect:

```c
// Coordinates:
int x = 0; // x coordinate of foobar
int y = 0; // y coordinate of foobar
```

For multi-line comments, programmers **MUST** use `/* */`, **MUST** wrap to 80
columns, and **MUST** insert a space and a * on continuation lines.

Correct:

```c
/*
 * Quae et nisi et a amet est quae est. Doloremque eum praesentium error quas
 * autem. Modi quo suscipit adipisci. Fugiat vero non neque neque velit qui.
 * Facilis quos reprehenderit et beatae quaerat sunt sapiente.
 */
```

Permissible:

```c
/* Quae et nisi et a amet est quae est. Doloremque eum praesentium error quas
 * autem. Modi quo suscipit adipisci. Fugiat vero non neque neque velit qui.
 * Facilis quos reprehenderit et beatae quaerat sunt sapiente. */
```

Incorrect:

```c
/* Quae et nisi et a amet est quae est. Doloremque eum praesentium error quas
 * autem. Modi quo suscipit adipisci. Fugiat vero non neque neque velit qui.
 * Facilis quos reprehenderit et beatae quaerat sunt sapiente.
 */

/* 
 * Quae et nisi et a amet est quae est. Doloremque eum praesentium error quas
 * autem. Modi quo suscipit adipisci. Fugiat vero non neque neque velit qui.
 * Facilis quos reprehenderit et beatae quaerat sunt sapiente. */

/*
* Quae et nisi et a amet est quae est. Doloremque eum praesentium error quas
* autem. Modi quo suscipit adipisci. Fugiat vero non neque neque velit qui.
* Facilis quos reprehenderit et beatae quaerat sunt sapiente.
*/

// Quae et nisi et a amet est quae est. Doloremque eum praesentium error quas
// autem. Modi quo suscipit adipisci. Fugiat vero non neque neque velit qui.
// Facilis quos reprehenderit et beatae quaerat sunt sapiente.
```

Programmers **SHOULD NOT** comment excessively, preferring to write code which
can be understood without clarification.

## Function declarations

Programmers **MUST declare functions with the following style:**

```c
static int
my_function(parameters...)
{
        /* function body */
}
```

- Placing the name at the start of the line makes it easier to find functions in
  a large codebase with e.g. `git grep '^my_function'`
- See [splitting long lines](#splitting-long-lines) for advice on splitting up
  functions with many parameters.

Programmers **MUST declare prototypes with the following style:**

```c
int my_function(parameters...);
```

- This excludes prototypes from the grep example shown in the previous rule.

## goto

Programmers **SHOULD use goto to deduplicate error handling.**

- If your function has many error cases and has to clean up any resources before
  exiting in an error condition, you should have an error: label and goto to it
  to perform this cleanup.

## Header files

Programmers **MUST add include guards.**

Use the format `${PROJECT}_${HEADER_PATH}_H` for the macro.

Example:

```c
#ifndef MYPROJECT_MYSUBDIR_FOOBAR_H
#define MYPROJECT_MYSUBDIR_FOOBAR_H

/* declarations... */

#endif
```

Programmers **MUST NOT use #pragma once.**

This is a GCC extension, see [features to avoid](#features-to-avoid).

Headers **MUST include only prototypes, type declarations, and documentation.**

Do not include inline functions or macros, see [features to
avoid](#features-to-avoid).

Programmers **MUST alpha-sort their headers, and group by locality.**

- First include external (`<>`) headers, then internal headers (`""`),
  then sort them alphabetically within their groups.
- Order-sensitive headers MUST be included all at once upfront, then followed
  by the remaining headers sorted according to the previous rule.
  However, order-sensitive headers SHOULD NOT be used if possible.

Programmers **SHOULD NOT include other headers.**

- If you need a struct with a defined storage type (for inlining), you MAY
  include the header which defines it.
- If you need a struct to take a pointer to, you SHOULD forward declare an
  opaque struct.

  ```c
  struct my_struct;

  void unrelated_module_state_add(const struct my_struct *ref);
  ```
- Headers which define standard types (`stdint.h`, `stddef.h`, etc) are excepted
  from this rule.

## Space placement

Programmers **MUST place spaces between control flow keywords and parenthesis.**

Correct:

```c
if (...) {
}

for (...) {
}

while (...) {
}
```

Incorrect:

```c
if(...) {
}

for(...) {
}

while(...) {
}
```

Programmers **MUST NOT place inner spaces in parenthesized expressions.**

Correct:

```c
function_call(1, 2, 3);
if (x == y);
```

Incorrect:

```c
function_call( 1, 2, 3 );
if ( x == y );
```

Programmers **MUST place spaces around binary operators.**

Correct:

```c
function_call(x + y * 2);
```

Incorrect:

```c
function_call(x+y*2);
```

## Splitting long lines

Programmers **SHOULD NOT split lines which are less than 80 columns.**

Programmers **MUST double-indent continuation lines for new scopes.**

Correct:

```c
if (is_valid_foobar(possible_foobar)
                && get_number_of_foobars(possible_foobar) > 10
                && is_application_ready()) {
        /* Do work */
}

int
do_foobar_work(struct foobar *foo, struct foobar *bar,
                struct foobar *baz, struct foobar *bet)
{
        /* Do work */
}
```

Incorrect:

```c
if (is_valid_foobar(possible_foobar)
        && get_number_of_foobars(possible_foobar) > 10
        && is_application_ready()) {
        /* Do work */
}

int
do_foobar_work(struct foobar *foo, struct foobar *bar,
        struct foobar *baz, struct foobar *bet)
{
        /* Do work */
}
```

- This visually distinguishes new scope from its parent.

Programmers **MUST single-indent continuation lines in the same scope.**

Correct:

```c
int
main(int argc, char *argv[])
{
    do_program_work("hello world",
        argc, argv);
    return 0;
}
```

Incorrect:

```c
int
main(int argc, char *argv[])
{
    do_program_work("hello world",
            argc, argv);
    return 0;
}
```

Programmers **MUST place operators on the next line.**

Correct:

```c
if (is_a_foobar(possible_foobar)
        && get_number_of_foobars(possible_foobar) > 10
        && is_application_ready()) {
    /* Do work */
}
```

Incorrect:

```c
if (is_a_foobar(possible_foobar) &&
        get_number_of_foobars(possible_foobar) > 10 &&
        is_application_ready()) {
    /* Do work */
}
```

- This makes the flow of the code easier to see at a glance, especially with
  respect to short-circuiting.

Programmers **MUST NOT align parameters with the opening '('.**

Incorrect:

```c
int do_work(struct foobar *foo,
            struct foobar *bar,
            struct foobar *baz,
            struct foobar *bet);
```

Correct:

```
int do_work(struct foobar *foo, struct foobar *bar,
        struct foobar *baz, struct foobar *bet);
```

- This is difficult to accomplish with tab indentation, and leaves a lot of
  wasted whitespace at the beginning of each line. Pushing up against the 80
  column limit encourages shorter variable names, longer function names, and
  other undesirable code traits.

Programmers **SHOULD split long string literals into multiple lines.**

When long strings hit 80 columns, terminate the string and resume it on the
following line.

```c
        fprintf(stderr, "%s:%d:%d: error: every foo must have a corresponding "
                "'bar' declaration.", filename, lineno, colno);
```

- Split strings word-wise and place the space on the first line.

Programmers **SHOULD split long lines with left-right balance.**

Try to make it "look good" by drawing a vertical line at 40 columns and
"balancing" characters on either side. This is a subjective rule.

## Struct and union declarations

Programmers **MUST** declare structs and unions with the `{` on the first line,
and `};` on its own line.

Correct:

```c
struct my_struct {
    int field_a;
    int field_b;
    int field_c;
};

union my_union {
    int i;
    long l;
    double d;
};
```

Incorrect:

```c
struct my_struct
{
    int field_a;
    int field_b;
    int field_c;
};

union my_union
{
    int i;
    long l;
    double d;
};
```

Programmers **MUST** place the name of an inline struct or union field on the
same line as `}` and `;`.
Correct:

```c
struct my_struct {
    struct {
        int a, b,c;
    } nested_struct;

    struct {
      int a, b, c;
    }; /* Anonymous */

    union {
        int a, b,c;
    } nested_union;
};
```

Incorrect:

```c
struct my_struct {
    struct {
        int a, b,c;
    }
    nested_struct;

    union {
        int a, b,c;
    }
    nested_union;
};
```

## Variable declarations

Programmers **MUST place \* next to the binding when declaring pointers.**

Correct:

```c
void do_work(struct my_struct *in);
struct my_struct *foobar = NULL;
```

Incorrect:

```c
void do_work(struct my_struct* in);
struct my_struct* foobar = NULL;
```

The operator has right associativity. When declaring multiple variables in one
statement, the asterisk will be misleading:

```c
struct my_struct* foobar, foobaz;
```

The second variable is not a pointer. For consistency, however, even
single-variable declarations must place the asterisk to the right.

Programmers **MUST USE a typedef for function pointers which are the parameters
to other functions.**

Correct:

```c
typedef void (*foobar_callback_func)(struct foobar *, void *);

void foobar_run(struct foobar *fb, foobar_callback_func cb, void *user);
```

Incorrect:

```c
void foobar_run(struct foobar *fb,
        void (*cb)(struct foobar *, void *), void *user);
```

- Typedefs are usually a bad idea, but function pointers are so verbose and
  weird and difficult to read that typedefs help out here.
- Many functions which take a function pointer pass some of their own parameters
  through to the callback - violating DRY since you have to specify them several
  times.

## Variable and function naming

Programmers **SHOULD name public functions with the following format:**

```
$NAMESPACE_$VERB(...);
$NAMESPACE_$NOUN_$VERB(...);
```

For example:

```
void example_run(...);
void example_foobar_update(...);
```

Programmers **SHOULD omit the namespace for static functions.**

However, the ordering of noun/verb is more subjective:

```
static void process_events(...);
static struct foobar *foobar_from_foobaz(...);
```

Programmers **MUST use the verbs "create" and "destroy" for heap objects:**

```c
struct my_struct *my_struct_create(...);
void my_struct_destroy(struct my_struct *in);
```

Programmers **MUST use the verbs "init" and "finish" for stack objects:**

```c
void my_struct_init(struct my_struct *in, ...);
void my_struct_finish(struct my_struct *in);
```

Programmers **SHOULD use nouns to name variables.**

Programmers **MAY use short variable names if their usage is clear.**

- Nested loops with an index variable SHOULD call the indicies i, j, and k; or
  x, y, z for coordinates. If you nest more than 3 loops your code is probably
  bad.
- Lengths may be called "l" or "ln", return values from `read` et al "n", sizes
  "sz", characters "c" or "ch", strings "s" or "str", operands named "val", etc.
