#!/usr/bin/env python3
"""Install a complete skill into an explicit macOS/Linux project, without home config changes."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import math
import os
import re
import shutil
import stat
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'plugins/job-search/skills/job-search'
SKILL_FILES = (
    'LICENSE', 'SKILL.md', 'agents/openai.yaml',
    'config/defaults.json', 'config/exclusions.json', 'config/sources.json',
    'references/applications.md', 'references/execution.md', 'references/onboarding.md',
    'references/search.md', 'references/state-and-cli.md', 'scripts/job_search.py',
    'templates/approval.json', 'templates/execution.json', 'templates/packet.md',
    'templates/posting.json', 'templates/profile.json', 'templates/receipt.json',
)


def _ignored(path, root):
    return '__pycache__' in path.relative_to(root).parts or path.suffix == '.pyc' or path.name == '.DS_Store'


def _snapshot(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Missing or symlinked skill directory')
    paths = list(root.rglob('*'))
    if any(p.is_symlink() for p in paths):
        raise ValueError('Symlinked package content refused')
    actual = {p.relative_to(root).as_posix(): p for p in paths if p.is_file() and not _ignored(p, root)}
    if set(actual) != set(SKILL_FILES):
        raise ValueError('Skill file set is incomplete or contains unrecognized files; inspect the package')
    data = {name: path.read_bytes() for name, path in actual.items()}
    skill = data['SKILL.md'].decode('utf-8')
    front = skill.split('\n---\n', 1)
    if not skill.startswith('---\n') or len(front) != 2:
        raise ValueError('Invalid Job Search skill frontmatter')
    fields = {}
    # This package uses two flat scalar fields, a conservative YAML subset.
    # Do not pretend to validate arbitrary YAML without a runtime dependency.
    for line in front[0].splitlines()[1:]:
        match = re.fullmatch(r'(name|description): (.+)', line)
        if not match or match[1] in fields:
            raise ValueError('Unsupported or malformed skill frontmatter; inspect the package')
        value = match[2]
        if value.startswith('"'):
            value = json.loads(value)
        elif (not value[0].isalpha() or ': ' in value or ' #' in value
              or value.casefold() in ('true', 'false', 'null', 'yes', 'no', 'on', 'off')):
            raise ValueError('Unsupported or malformed skill scalar; inspect the package')
        if not isinstance(value, str) or not value.strip():
            raise ValueError('Skill metadata must contain nonblank text')
        fields[match[1]] = value
    if fields.get('name') != 'job-search' or set(fields) != {'name', 'description'}:
        raise ValueError('Invalid Job Search skill identity or description')
    parsed = {}
    for name, raw in data.items():
        if name.endswith('.json'):
            parsed[name] = json.loads(raw)
            if not isinstance(parsed[name], dict):
                raise ValueError('Package JSON must contain an object: ' + name)
    registry = parsed['config/sources.json'].get('sources')
    if (not isinstance(registry, list) or not registry
            or not all(isinstance(s, dict) and isinstance(s.get('id'), str) and s['id'].strip()
                       and type(s.get('enabled_by_default')) is bool and s.get('configured_targets') == []
                       for s in registry)
            or len({s['id'] for s in registry}) != len(registry)):
        raise ValueError('Malformed or preconfigured source registry')
    for key in ('exact_company_aliases', 'distinctive_route_tokens'):
        values = parsed['config/exclusions.json'].get(key)
        if not isinstance(values, list) or not values or not all(isinstance(v, str) and v.strip() for v in values):
            raise ValueError('Malformed prop-firm exclusions')
    defaults = parsed['config/defaults.json']
    for key in ('posting_fresh_hours', 'submission_fresh_minutes', 'source_recheck_days',
                'read_attempts_per_source', 'read_timeout_seconds', 'source_budget_seconds', 'file_picker_attempts'):
        value = defaults.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError('Invalid package limit: ' + key)
    if defaults.get('assistance_level') != 'prepare_only' or defaults.get('standing_scope') is not None:
        raise ValueError('Package defaults must start without application authority')
    for key in ('auto_spend', 'auto_contract', 'outreach', 'telemetry', 'network_in_helper', 'customer_data_in_package'):
        if defaults.get(key) is not False:
            raise ValueError('Unsafe or malformed package default: ' + key)
    return data


@contextmanager
def _project_lock(project):
    # The OS releases the advisory lock if the process exits or is killed.
    # The persistent file is outside the host's skill-discovery tree.
    path = project / '.job-search-install.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        lock_stat = os.fstat(fd)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1:
            raise ValueError('Install lock must be a regular file without additional links')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Another Job Search installer is running in this project; retry after it finishes') from exc
        yield
    finally:
        os.close(fd)


def _parents(project, create=False):
    for parent in (project / '.agents', project / '.agents/skills'):
        if parent.is_symlink():
            raise ValueError('Symlinked install parent refused')
        if create:
            parent.mkdir(exist_ok=True)
        if parent.exists() and not parent.is_dir():
            raise ValueError('Install parent is not a directory')


def _check_chain(chain):
    for parent_fd, name, child_fd in chain:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(child_fd)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('Install parents changed; inspect the project before retrying')


@contextmanager
def _publication_directory(project):
    descriptors = [os.open(project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    chain = []
    try:
        for name in ('.agents', 'skills'):
            parent_fd = descriptors[-1]
            try:
                os.mkdir(name, dir_fd=parent_fd)
            except FileExistsError:
                pass
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            descriptors.append(child_fd)
            chain.append((parent_fd, name, child_fd))
        _check_chain(chain)
        yield descriptors[-1], chain
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def install(project):
    project = Path(project).expanduser().resolve(strict=True)
    if not project.is_dir() or project in (Path(project.anchor), Path.home(), Path.home() / '.agents', Path.home() / '.codex'):
        raise ValueError('Choose a dedicated project directory, not a filesystem or user-settings root')
    for parent in (SOURCE, SOURCE.parent, SOURCE.parent.parent, SOURCE.parent.parent.parent):
        if parent.is_symlink():
            raise ValueError('Symlinked package content refused')
    expected = _snapshot(SOURCE)
    dest = project / '.agents/skills/job-search'
    with _project_lock(project):
        _parents(project)
        if dest.exists() or dest.is_symlink():
            try:
                identical = _snapshot(dest) == expected
            except (ValueError, OSError, UnicodeError):
                identical = False
            if identical:
                return dest
            raise ValueError('Different or incomplete Job Search already exists here; inspect and preserve it before updating')
        # Stage outside .agents/skills so a failed or interrupted copy cannot be
        # exposed as an installed skill. A killed process can leave this hidden
        # staging directory, but a later install can safely start anew.
        stage = Path(tempfile.mkdtemp(prefix='.job-search-install-', dir=project))
        try:
            copied = stage / 'job-search'
            shutil.copytree(SOURCE, copied, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store'))
            if _snapshot(copied) != expected:
                raise ValueError('Package changed during copy; no skill installed')
            with _publication_directory(project) as (directory_fd, chain):
                try:
                    os.stat('job-search', dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('Install destination appeared during staging; preserved without overwrite')
                # Hold verified directory descriptors so a substituted parent
                # symlink cannot redirect publication to another directory.
                os.rename(copied, 'job-search', dst_dir_fd=directory_fd)
                _check_chain(chain)
        finally:
            shutil.rmtree(stage)
        return dest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', required=True, type=Path)
    args = p.parse_args()
    try:
        print(install(args.project))
        print('Complete skill present (installed or already identical). Start a session in this project and invoke $job-search. Host discovery must be verified there.')
    except (ValueError, OSError, UnicodeError) as exc:
        p.exit(2, str(exc) + '\n')
