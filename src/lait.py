# lait.py
# Build and Install package from spec file.
#
# Copyright (C) 2016 1dot75cm
#

from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function
from operator import itemgetter
from dnfpluginscore import _, logger
try:
    from subprocess import getoutput as sh
    from subprocess import getstatusoutput as rsh
    from urllib.request import urlretrieve
    import urllib.error
except ImportError as e:
    from commands import getoutput as sh
    from commands import getstatusoutput as rsh
    from urllib import urlretrieve

import dnf
import dnf.cli
import dnf.exceptions
import dnfpluginscore.lib
import argparse
import functools
import fnmatch
import shutil
import json
import rpm
import sys
import os
import re

def save_to_file(filename, content, operate='w+'):
    ''' Save repo to file '''
    try:
        with open(filename, operate) as fd:
            dnf.pycomp.write_to_file(fd, content)
            os.chmod(filename, 0o644)
    except (IOError, OSError) as e:
        logger.error(_('Could not save repo to repofile %s: %s'),
                     filename, e)
        return False
    return True

def find(pattern, path=os.getcwd()):
    ''' Search specify file '''
    for root, dirs, files in os.walk(path):
        for filename in fnmatch.filter(files, pattern):
            yield os.path.join(root, filename)

def echo(*args):
    ''' Output log with color

    Xterm 256color chart: https://en.wikipedia.org/wiki/Xterm
    The control sequences, see console_codes(4) man page.
    '''
    content = ''
    for i,v in enumerate(args):
        fg = '38;5;' if v.endswith('f') else ''
        bg = '48;5;' if v.endswith('b') else ''
        value = v[0:-1] if v.endswith('f') or v.endswith('b') else v
        if re.search('^[0-9]{1,3};*', v):
            content += '\033[' + fg + bg + value + 'm'
        elif re.search('^[0-9]{1,3};*', args[i-1]):
            content += v + '\033[0m'
        else:
            content += v
    print(content)

class sink_rpm_logging(object):
    def __init__(self):
        self.sink = None

    def __call__(self, func):
        @functools.wraps(func)
        def inner(*args, **kwds):
            with self:
                return func(*args, **kwds)
        return inner

    def __enter__(self):
        self.sink = open('/dev/null', 'w')
        rpm.setLogFile(self.sink)

    def __exit__(self, exc_type, exc, exc_tb):
        self.sink.close()

class ArgumentParser(dnfpluginscore.ArgumentParser):

    def __init__(self, cmd="", **kwargs):
        try:
            dnfpluginscore.ArgumentParser.__init__(self, cmd, **kwargs)
        except TypeError as e:
            argparse.ArgumentParser.__init__(self, **kwargs)

class Lait(dnf.Plugin):

    name = 'lait'

    def __init__(self, base, cli):
        super(Lait, self).__init__(base, cli)
        if cli:
            cli.register_command(LaitCommand)

class LaitCommand(dnf.cli.Command):
    ''' Lait plugin for DNF '''

    aliases = ('lait', 'spec')
    summary = _('Build and Install package from spec file')
    usage = _('''
subcommand:
  add-repo            add spec repo
  install <pkg...>    build and install the spec file
  rebuild <pkg...>    rebuild the spec file
  remove <pkg...>     remove the spec file
  search <name>       search the spec file

optional arguments:
  --help-cmd            show this help about this tool
  -a ARCH, --arch ARCH  set architecture for build rpm package
  -r, --release RELEASE set release version for build rpm package
  --mock-opts OPTIONS   set mock command-line options
  --createrepo          run createrepo to create repository
  --createcache         create metadata cache
  --result PATH         log bulid result to file (default: result.log)
  --verbose-cmd         verbose operation
  --quiet-cmd           quiet operation
''')

    offical = ['@System', 'fedora', 'updates', 'updates-testing']
    gitdir = os.path.join('/var/cache/dnf/specs')
    srcdir = os.path.join(gitdir, 'Builds')
    outdir = os.path.join(gitdir, 'Output')
    cachefile = os.path.join(gitdir, '.repocache.json')
    if os.path.exists(cachefile):
        echo('32', 'info:', ' Load cache from {} file.'.format(cachefile))
        with open(cachefile, 'r') as f:
            pkgdict = json.load(f)
    results = []
    resultfile = os.path.join(gitdir, 'result.log')

    def __init__(self, cli):
        super(LaitCommand, self).__init__(cli)
        self.opts = None
        self.parser = None
        # Get the reposdir location
        self.repodir = dnfpluginscore.lib.get_reposdir(self)

    @staticmethod
    def set_argparser(parser):
        ''' Parser for command-line options '''
        subparsers = parser.add_subparsers(title='subcommands')
        add_repo = subparsers.add_parser('add-repo', help=_('add spec repo'))
        add_repo.add_argument(dest='add_repo', type=str, action='store', nargs='*')
        install = subparsers.add_parser('install', help=_('build and install the spec file'))
        install.add_argument(dest='install', type=str, action='store', nargs='*')
        #list = subparsers.add_parser('list', help=_('list spec in repository'))
        #list.add_argument(dest='list', type=str, action='store', nargs='*')
        rebuild = subparsers.add_parser('rebuild', help=_('rebuild the spec file'))
        rebuild.add_argument(dest='rebuild', type=str, action='store', nargs='*')
        remove = subparsers.add_parser('remove', help=_('remove the spec file'))
        remove.add_argument(dest='remove', type=str, action='store', nargs='*')
        search = subparsers.add_parser('search', help=_('search the spec file'))
        search.add_argument(dest='search', type=str, action='store', nargs='*')
        #update = subparsers.add_parser('update', help=_('update the spec file'))
        #update.add_argument(dest='update', type=str, action='store', nargs='*')

        parser.add_argument('-a', '--arch', metavar='ARCH', type=str, action='append',
                            help=_('set architecture for build rpm package'))
        parser.add_argument('-r', '--release', metavar='RELEASE', type=str, action='append',
                            help=_('set release version for build rpm package'))
        parser.add_argument('--mock-opts', metavar='OPTIONS', type=str, action='store', default='',
                            help=_('set mock command-line options'))
        parser.add_argument('--createrepo', action='store_true',
                            help=_('run createrepo to create repository'))
        parser.add_argument('--createcache', action='store_true',
                            help=_('create metadata cache'))
        parser.add_argument('--result', metavar='PATH', type=str, action='store', default='result.log',
                            help=_('log bulid result to file (default: result.log)'))
        parser.add_argument('--verbose-cmd', action='store_true',
                            help=_('verbose operation'))
        parser.add_argument('--quiet-cmd', action='store_true',
                            help=_('quiet operation'))
        return parser

    def configure(self, args):
        # parser arguments
        self.parser = self.set_argparser(ArgumentParser(self.aliases[0], description=_(self.summary)))
        self.opts = self.parser.parse_args(args)

        if len(sys.argv) > 2 and \
           'add_repo' not in dir(self.opts) and \
           'search' not in dir(self.opts):
            demands = self.cli.demands
            demands.available_repos = True
            demands.resolving = True
            demands.root_user = True
            demands.sack_activation = True

    @sink_rpm_logging()
    def run(self, args):
        # load build result
        if os.path.exists(self.resultfile):
            if self.opts.verbose_cmd:
                echo('36', 'verb:', ' load build result from %s file.' % self.resultfile)
            with open(self.resultfile) as f:
                self.results = re.findall('.*.spec', f.read())

        if hasattr(self.opts, 'add_repo') and self.opts.add_repo:
            self.add_repo()
            self.get_repo()
        elif hasattr(self.opts, 'install') and self.opts.install:
            # build rpm
            self.build_pkg()
            # add local repository
            repoid = 'lait'
            reponame = 'created by dnf lait for local repo'
            url = 'file:///%s/$releasever/$basearch/' % self.outdir
            destname = os.path.join(self.repodir, "%s.repo" % repoid)
            content = "[%s]\nname=%s\nbaseurl=%s\nenabled=1\ngpgcheck=0" % (repoid, reponame, url)
            save_to_file(destname, content)
        elif hasattr(self.opts, 'remove') and self.opts.remove:
            for spec in self._get_spec('remove'):
                for pkg in self.pkgdict[spec]['provides']:
                    echo('32', 'info:', ' Uninstalling %s package' % pkg)
                    self.operate_pkg('remove', pkg)
        elif hasattr(self.opts, 'search') and self.opts.search:
            for i in self.opts.search:
                for j in find('*%s*.spec'%i, self.gitdir):
                    print(j)
        elif self.opts.createcache:
            if os.path.exists(self.cachefile):
                echo('32', 'info:', ' The repo cache exists.')
            else:
                echo('32', 'info:', ' Create repo cache.')
                self.repo_cache(self.cachefile, self.opts.verbose_cmd)
        else:
            print(self.summary, '\n', self.usage)

    def build_pkg(self):
        ''' Package build process '''
        pkgs, deps = [], {}
        resultList = []
        archs = self.opts.arch if self.opts.arch else [os.uname()[-1]]
        releases = self.opts.release if self.opts.release else [sh('rpm -E %fedora')]
        rootdir = self.outdir

        # build srpm
        for spec in self.parse_dep(self._get_spec('install')):
            if spec in self.results:
                if self.opts.verbose_cmd:
                    echo('36', 'verb:', ' skip %s file.' % (spec))
                continue

            specFile, specDict = self.parse_spec(spec, self.gitdir)
            if self.opts.verbose_cmd:
                echo('36', 'verb:', ' parser {} file.'.format(specFile))
            self.get_sources(specDict['sources'], self.srcdir)
            srpmFile = self.build_srpm(specFile, self.srcdir)
            echo('32', 'info:', ' Build SRPM -', srpmFile)
            if re.match('.*\.net', srpmFile):
                key = specDict['name'] + '.net'
            else:
                key = specDict['name']
            # queue
            pkgs.append(key)
            deps.update({key: [specDict['build_requires'], specDict['provides'], srpmFile, specFile],})

        tasks, specs = self.resolve_depends(pkgs, deps)
        # build rpm
        for task in tasks:
            for rel in releases:
                for arch in archs:
                    outDir = os.path.join(rootdir, rel, arch)
                    echo('32', 'info:', ' Build RPM {} for fc{} - {}:'.format(task, rel, arch))
                    value, log = self.build_rpm(task, release=rel, arch=arch,
                                                output=outDir, opts=self.opts.mock_opts,
                                                verb=self.opts.verbose_cmd, quiet=self.opts.quiet_cmd)
                    if self.opts.verbose_cmd:
                        echo(log)
                    echo('32', 'info:', ' Create metadata for fc{} - {}:\n'.format(rel, arch))
                    self.create_repo(outDir, verb=self.opts.verbose_cmd, quiet=self.opts.quiet_cmd)
                    self.result(self.resultfile, [value, specs[tasks.index(task)], rel, arch])
                    resultList.append(self.result('-', [value, task, rel, arch]))

        echo('36', '\n** Build result **')
        for i in resultList:
            echo(''.join(i))

        # install rpm
        for spec in specs:
            for pkg in self.pkgdict[spec]['provides']:
                echo('32', 'info:', ' Installing %s package' % pkg)
                self.operate_pkg('install', pkg)

    def operate_pkg(self, operate, pkgname):
        try:
            eval('self.base.%s("%s")' % (operate, pkgname))
        except dnf.exceptions.MarkingError:
            msg = _("No matching package to install: '%s'")
            logger.warning(msg, pkgname)
            return False
        return True

    def add_repo(self):
        ''' process --add-repo option '''
        for url in self.opts.add_repo:
            if dnf.pycomp.urlparse.urlparse(url).scheme == '':
                url = 'file://' + os.path.abspath(url)
            logger.info(_('Adding repo from: %s'), url)
            if url.endswith('.repo'):
                # .repo file - download, put into reposdir and enable it
                destname = os.path.basename(url)
                destname = os.path.join(self.repodir, destname)
                try:
                    f = dnfpluginscore.lib.urlopen(self, None, url, 'w+')
                    shutil.copy2(f.name, destname)
                    os.chmod(destname, 0o644)
                    f.close()
                except IOError as e:
                    logger.error(e)
                    continue
            else:
                # just url to repo, create .repo file on our own
                repoid = '%s-%s' % (url.split('/')[-2], url.split('/')[-1])
                destname = os.path.join(self.repodir, "lait.spec")
                content = "%s %s\n" % (repoid, url)
                if not save_to_file(destname, content, 'a+'):
                    continue

    def get_repo(self):
        ''' git clone '''
        if not os.path.exists(self.gitdir):
            os.mkdir(self.gitdir)

        # read spec files
        for repo in find('*.spec', '/etc/yum.repos.d'):
            with open(repo, 'r') as f:
                content = f.read()
                repoid = re.search('(.*?)\s', content).group(1)
                url = re.search('\s(.*)', content).group(1)
            if os.path.exists(os.path.join(self.gitdir, repoid, '.git')):
                os.chdir(os.path.join(self.gitdir, repoid))
                rsh('/bin/git pull')
            else:
                rsh('/bin/git clone --depth 1 %s %s' % (url,
                    os.path.join(self.gitdir, repoid)))

    def _get_spec(self, operate):
        ''' Read spec files '''
        fnlist = []
        for spec_fn in find('*.spec', self.gitdir):
            for spec_in in eval('self.opts.%s' % operate):
                if spec_in + '.spec' in spec_fn.split('/')[-1]:
                    fnlist.append(spec_fn)
                else:
                    continue
        return fnlist

    def _query_package(self, query):
        ''' Query package name from remote repository '''
        if 'repos' not in globals().keys():
            echo('32', 'info:', ' Initial metadata for repository.')
            global repos
            repos = dnf.Base()
            repos.read_all_repos()
            repos.fill_sack(load_available_repos=True)
        return list(repos.provides(query))

    def _query_key(self, query):
        ''' Query repocache.json's key by pkgname '''
        keys = [i[0] for i in self.pkgdict.items() if query in i[1]['provides']]
        return keys if keys else False

    def parse_dep(self, specs):
        ''' Generate buildrequires list '''
        for spec in specs:
            _, specDict = self.parse_spec(spec)
            for i in specDict['build_requires']:
                if self._query_package(i)[-1].repoid in self.offical:
                    continue
                keys = self._query_key(i)
                if keys and keys[0] in specs:
                    continue
                else:
                    specs.append(keys[0])
        return specs

    def parse_spec(self, specFile, cacheFile='.repocache.json'):
        ''' Parse the Spec file contents '''
        if self.pkgdict:
            return specFile, self.pkgdict[specFile]

        items = lambda t, c: re.findall('%s:\s+(.*)'%t, c)
        split_str = lambda l: [re.split('[\s,=|>=|<=]+', i) for i in l]
        flat = lambda L: sum(map(flat, L), []) if isinstance(L, list) else [L]
        remove_ver = lambda l: [i for i in l if not re.match('^[0-9]', i)]
        decode = lambda v: v.decode() if v else v

        if os.path.exists(specFile) and specFile.endswith('.spec'):
            rpm_info = {}
            subpkgs, reqpkgs = [], []
            spec = rpm.spec(specFile)
            hdr = spec.sourceHeader

            reqlist = [decode(i) for i in hdr[rpm.RPMTAG_REQUIRES]]
            content = sh('/bin/rpmspec -P {}'.format(specFile))
            content = content[:content.index('%changelog')]

            # subpackages
            name = decode(hdr[rpm.RPMTAG_NAME])
            subpkgs.append(name)
            if re.search('%package', content):
                for i in re.findall('%package\s*(.+)', content):
                    if i.startswith('-n'):
                        subpkgs.append(re.match('-n\s*(.*)', i).group(1))
                    else:
                        subpkgs.append('{}-{}'.format(name, i))

            provpkgs = remove_ver(flat(split_str(items('Provides', content)))) + subpkgs

            # parse buildrequires
            for i in reqlist:
                if re.match('.*\((.*)\)', i):
                    reqpkgs.append(self._query_package(i)[0].name)
                else:
                    reqpkgs.append(i)

            rpm_info = {
                "name": decode(hdr[rpm.RPMTAG_NAME]),
                "epoch": hdr[rpm.RPMTAG_EPOCHNUM],
                "version": decode(hdr[rpm.RPMTAG_VERSION]),
                "release": decode(hdr[rpm.RPMTAG_RELEASE]),
                "vendor": decode(hdr[rpm.RPMTAG_VENDOR]),
                "summary": decode(hdr[rpm.RPMTAG_SUMMARY]),
                "packager": decode(hdr[rpm.RPMTAG_PACKAGER]),
                "group": decode(hdr[rpm.RPMTAG_GROUP]),
                "license": decode(hdr[rpm.RPMTAG_LICENSE]),
                "url": decode(hdr[rpm.RPMTAG_URL]),
                "description": decode(hdr[rpm.RPMTAG_DESCRIPTION]),
                "sources": spec.sources,
                "patchs": [decode(i) for i in hdr[rpm.RPMTAG_PATCH]],
                "build_archs": [decode(i) for i in hdr[rpm.RPMTAG_BUILDARCHS]],
                "exclusive_archs": [decode(i) for i in hdr[rpm.RPMTAG_EXCLUSIVEARCH]],
                #"build_requires": [i.DNEVR()[2:] for i in rpm.ds(hdr, 'requires')],
                "build_requires": sorted(list(set(reqpkgs))),
                "requires": remove_ver(flat(split_str(items('\nRequires', content)))),
                "recommends": remove_ver(flat(split_str(items('Recommends', content)))),
                "supplements": [decode(i) for i in hdr[rpm.RPMTAG_SUPPLEMENTS]],
                "suggests": [decode(i) for i in hdr[rpm.RPMTAG_SUGGESTS]],
                "enhances": [decode(i) for i in hdr[rpm.RPMTAG_ENHANCES]],
                "provides": sorted(list(set(provpkgs))),
                "obsoletes": remove_ver(flat(split_str(items('Obsoletes', content)))),
                "conflicts": remove_ver(flat(split_str(items('Conflicts', content))))
            }

            return specFile, rpm_info
        return False

    def get_sources(self, itemList, output=None, verb=None):
        ''' Get source files from local and internet '''
        if not os.path.isdir(output):
            os.mkdir(output)

        for item in itemList:
            if not os.path.exists(os.path.join(output, item[0].split('/')[-1])):
                if item[0].split('://')[0] in ['http', 'https', 'ftp']:
                    if verb:
                        echo('36', 'verb:', ' downloading {} file.'.format(item[0]))
                    try:
                        urlretrieve(item[0], '{}/{}'.format(output, item[0].split('/')[-1]))
                        #call(['wget', '-q', '-P', output, item[0]])
                    except Exception as e:
                        echo('31', 'erro:', ' downloading error. {}'.format(e))
                        sys.exit(1)
                else:
                    for src in find(item[0], self.gitdir):
                        if verb:
                            echo('36', 'verb:', ' copy {} file to build directory.'.format(src))
                        shutil.copy(src, output)

    def build_srpm(self, specFile, output='build'):
        ''' Build source rpm '''
        command = '/bin/rpmbuild ' \
            '-D "_topdir ." ' \
            '-D "_builddir {out}" ' \
            '-D "_buildrootdir {out}" ' \
            '-D "_rpmdir {out}" ' \
            '-D "_sourcedir {out}" ' \
            '-D "_specdir {out}" ' \
            '-D "_srcrpmdir {out}" ' \
            '-bs {}'.format(specFile, out=output)
        return re.search('/.*', sh(command)).group()

    def build_rpm(self, srpmFile, release='23', arch='x86_64', output=None, opts='',
                  verb=None, quiet=None):
        ''' Build binary rpm '''
        if verb:
            opts += ' --verbose'
        elif quiet:
            opts += ' --quiet'

        command = '/bin/mock --resultdir={} --root=fedora-{}-{}-lait {} {}'.format(
            output, release, arch, opts, srpmFile)
        return rsh(command)

    def create_repo(self, output=None, verb=None, quiet=None):
        ''' Creates metadata of rpm repository '''
        opts = ''
        if verb:
            opts += ' --verbose'
        elif quiet:
            opts += ' --quiet'

        return sh('/bin/createrepo_c {} -d -x *.src.rpm {}'.format(opts, output))

    def repo_cache(self, output=None, verb=None):
        ''' Create repository cache '''
        cacheDict = {}
        for i in find('*.spec', self.gitdir):
            if verb:
                echo('36', 'verb:', ' cached {} file.'.format(i))
            specFile, specDict = self.parse_spec(i, output)
            cacheDict.update({specFile: specDict})

        with open(output, 'w') as f:
            json.dump(cacheDict, f)

    def result(self, filename, content):
        ''' Log build result to file '''
        result = 'success' if content[0] == 0 else 'fail'
        _, pkgname, release, arch = content

        if filename == '-':
            _pkgname = re.match('.*/(.*-[0-9]{1,2}).*', pkgname).group(1)
            pkgname = _pkgname + '.net' if re.match('.*\.net', pkgname) else _pkgname
            return pkgname.ljust(35), \
                   'fc{}-{}'.format(release, arch).ljust(13), \
                   result
        else:
            with open(filename, mode='a+') as f:
                echo('32', 'info:', ' Write build result to {} file.'.format(filename))
                f.write('{} fc{}-{} {}\n'.format(pkgname, release, arch, result))

    def resolve_depends(self, pkglist, depdict, verb=None):
        ''' Resolve dependencies '''
        _tasks, _specs = [], []
        tasks, specs = [], []
        for pkg in pkglist:
            score = 0
            for dep in depdict[pkg][0]:
                for pkg2 in pkglist:
                    if pkg == pkg2:
                        continue
                    if dep in depdict[pkg2][1]:
                        score += 1
            _tasks.append({'pkg': depdict[pkg][2], 'score': score})
            _specs.append({'spec': depdict[pkg][3], 'score': score})

        tasks_by_score = sorted(_tasks, key=itemgetter('score'))
        specs_by_score = sorted(_specs, key=itemgetter('score'))
        for i in tasks_by_score:
            tasks.append(i['pkg'])
        for i in specs_by_score:
            specs.append(i['spec'])

        echo('32', 'info:', ' Resolve dependencies.')
        if verb:
            echo('36', 'verb:', ' build task {}.'.format(tasks))
        return tasks, specs
