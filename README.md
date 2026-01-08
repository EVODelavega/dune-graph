# Dune graph

While working on a sizeable OCaml mono-repo, I was struggling to get a clear picture of which dependencies were used where, and how. I wanted a simple dependency graph.
I'm sure that there is some way to use `dune describe` to get something actually usable, but I couldn't quite get what I was after, so instead I decided to build my own tool. 


## Usage

```sh
$ dune-graph -h
Analyze build targets and dependencies from dune files

Usage: dune-graph [OPTIONS]

Options:
      --format <FORMAT>  [default: text]
      --root <ROOT>      [default: .]
      --level <LEVEL>    Maximum depth level to resolve dependencies (e.g., --level 2)
      --target <TARGET>  Focus on a specific target (e.g., --target foobar)
  -p, --pattern          Use pattern matching for --target (matches substring like foo)
  -f, --full-graph       Include fully resolved dependency graph
  -u, --unique-list      Show list of all unique dependencies.
  -h, --help             Print help

```

To list all build targets in the project root, simply run

```sh
$ ./dune-graph --level 0
```

To get a list of all dependencies of a given build target:

```sh
# Include all unique dependencies by adding -u --unique-list
$ ./dune-graph --target foobar -u
# Or match a pattern/substring to specify one or more targets:
$ ./dune-graph --target foo --pattern -u
```


Optionally, with a full dependency graph to show how the unique packages are resolved:

```sh
$ ./dune-graph --target foobar -f
```

In some cases, the output is incredibly verbose, so it may be useful to specify a specific level. Keep in mind that level 0 is special: it resolves no dependencies, it's just a shortcut to list all build targets.


## Quick commands

Get a full list of dependencies of the overal project:

```sh
$ dune-graph -u
```

Same as above, but with a dependency graph:

```sh
$ dune-graph -f -u
```
