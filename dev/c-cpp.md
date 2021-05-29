# C/C++

## C Library Path

```text
$ echo '#include <sys/types.h>'' | gcc -E -x c - | grep '/types.h'
```

## Vangrind

```text
$ valgrind --leak-check=full --track-origins=yes --leak-resolution=med ./a.out
```

