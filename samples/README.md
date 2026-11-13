# Intentionally vulnerable samples

These files exist only to demonstrate DUMBBELL findings and to power the test
suite. Every credential is fake. Do not copy anything from this directory into
real projects.

The `multilang/` directory contains intentionally vulnerable Rust, TypeScript,
Go, Java, C#, Ruby, C, shell, Makefile, and plain-text samples. They show that
the scanner evaluates the same rules against every text file type.
