# dnf-plugin-lait

The lait plugins to use with [DNF package manager](https://github.com/rpm-software-management/dnf). The plugin is similar to [yaourt](https://github.com/archlinuxfr/yaourt), direct download the spec and building src.rpms locally and installing the binary .rpms.

## Building from source

From the Lait git checkout directory:

```bash
$ mkdir build
$ pushd build
$ cmake .. && make
$ sudo make install
```

Then to run Lait:

```bash
$ lait --help-cmd
$ lait add-repo https://github.com/FZUG/repo
$ lait search <name>
$ lait install <pkg...>
$ lait remove <pkg...>
```

