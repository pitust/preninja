# structure of a preninja config file
A preninja config file is written using yaml. It specifies a set of keys important to the build process:
 - rules: this describes the different rules that transform one kind of file into another
 - env: this describes variables usable for the rest of compilation, like cflags or ldflags
 - pkg-config: this describes the packages that need to be resolved
 - actions: the actions are things that can be performed
 - features: extra utilities that come with preninja

## rules
There are two kinds of rules: map rules and reduce rules. Map rules are like a compiler: they turn one file into another. Reduce rules are like a linker: they reduce a large amount of rules into just one file.

Map rules are more sofisticated than reduce ones: they