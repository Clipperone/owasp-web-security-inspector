import { execFileSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

const packageJsonPath = path.join(rootDir, 'package.json');
const packageLockPath = path.join(rootDir, 'package-lock.json');
const manifestPath = path.join(rootDir, 'manifest.json');

const npmExecutable = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const gitExecutable = process.platform === 'win32' ? 'git.exe' : 'git';

const VALID_BUMPS = new Set(['major', 'minor', 'patch']);

function parseArgs(argv) {
  const bump = argv.find(arg => VALID_BUMPS.has(arg));
  const options = {
    dryRun: argv.includes('--dry-run'),
    allowDirty: argv.includes('--allow-dirty'),
    skipChecks: argv.includes('--skip-checks'),
    skipTag: argv.includes('--skip-tag'),
  };

  if (!bump) {
    throw new Error('Usage: node scripts/release.mjs <major|minor|patch> [--dry-run] [--allow-dirty] [--skip-checks] [--skip-tag]');
  }

  return { bump, options };
}

function run(command, args, { stdio = 'pipe' } = {}) {
  if (process.platform === 'win32') {
    return execFileSync('cmd.exe', ['/d', '/s', '/c', command, ...args], {
      cwd: rootDir,
      encoding: 'utf8',
      stdio,
    });
  }

  return execFileSync(command, args, {
    cwd: rootDir,
    encoding: 'utf8',
    stdio,
  });
}

function assertCleanGitTree(allowDirty) {
  if (allowDirty) return;

  const status = run(gitExecutable, ['status', '--porcelain']).trim();
  if (status) {
    throw new Error('Working tree is not clean. Commit or stash changes first, or rerun with --allow-dirty.');
  }
}

function parseSemver(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) {
    throw new Error(`Unsupported version format: ${version}`);
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

function bumpVersion(version, bump) {
  const parsed = parseSemver(version);

  if (bump === 'major') {
    return `${parsed.major + 1}.0.0`;
  }
  if (bump === 'minor') {
    return `${parsed.major}.${parsed.minor + 1}.0`;
  }
  return `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`;
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

async function writeJson(filePath, data) {
  await writeFile(filePath, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

async function main() {
  const { bump, options } = parseArgs(process.argv.slice(2));
  assertCleanGitTree(options.allowDirty);

  const [pkg, lock, manifest] = await Promise.all([
    readJson(packageJsonPath),
    readJson(packageLockPath),
    readJson(manifestPath),
  ]);

  const currentVersion = pkg.version;
  if (lock.version !== currentVersion || lock.packages?.['']?.version !== currentVersion || manifest.version !== currentVersion) {
    throw new Error('Version mismatch detected across package.json, package-lock.json, and manifest.json. Sync them before releasing.');
  }

  const nextVersion = bumpVersion(currentVersion, bump);
  const releaseTag = `v${nextVersion}`;

  if (!options.dryRun) {
    pkg.version = nextVersion;
    lock.version = nextVersion;
    if (lock.packages?.['']) {
      lock.packages[''].version = nextVersion;
    }
    manifest.version = nextVersion;

    await Promise.all([
      writeJson(packageJsonPath, pkg),
      writeJson(packageLockPath, lock),
      writeJson(manifestPath, manifest),
    ]);
  }

  if (!options.skipChecks) {
    run(npmExecutable, ['run', 'lint'], { stdio: 'inherit' });
    run(npmExecutable, ['run', 'eslint'], { stdio: 'inherit' });
    run(npmExecutable, ['run', 'build'], { stdio: 'inherit' });
  }

  if (options.dryRun) {
    console.log(`Dry run completed. Next version: ${nextVersion}`);
    console.log(`Tag to create: ${releaseTag}`);
    return;
  }

  run(gitExecutable, ['add', 'package.json', 'package-lock.json', 'manifest.json'], { stdio: 'inherit' });
  run(gitExecutable, ['commit', '-m', `Release ${releaseTag}`], { stdio: 'inherit' });

  if (!options.skipTag) {
    run(gitExecutable, ['tag', releaseTag], { stdio: 'inherit' });
  }

  console.log(`Release prepared: ${releaseTag}`);
  console.log('Push with: git push --follow-tags');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});