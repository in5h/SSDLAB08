import axios from "axios";
import fs from "fs";
import path from "path";
import AdmZip from "adm-zip";

const githubApi = axios.create({
  baseURL: "https://api.github.com",
  headers: {
    Accept: "application/vnd.github+json",
  },
});

/**
 * Extract {owner, repo} from a GitHub URL like:
 * https://github.com/org/repo or https://github.com/org/repo.git
 */
export function parseGithubUrl(url) {
  try {
    const u = new URL(url);
    const [owner, repoRaw] = u.pathname.replace(/^\/+/, "").split("/");
    const repo = repoRaw.replace(/\.git$/, "");
    return { owner, repo };
  } catch {
    return null;
  }
}

/**
 * Fetch basic metadata + languages for a GitHub repo.
 */
export async function fetchRepoSummary(repoUrl, githubToken) {
  const parsed = parseGithubUrl(repoUrl);
  if (!parsed) {
    throw new Error("Invalid GitHub URL");
  }

  const { owner, repo } = parsed;

  const authHeaders = githubToken
    ? { Authorization: `Bearer ${githubToken}` }
    : {};

  const [repoRes, langsRes] = await Promise.all([
    githubApi.get(`/repos/${owner}/${repo}`, { headers: authHeaders }),
    githubApi.get(`/repos/${owner}/${repo}/languages`, { headers: authHeaders }),
  ]);

  return {
    owner,
    repo,
    full_name: repoRes.data.full_name,
    description: repoRes.data.description,
    default_branch: repoRes.data.default_branch,
    html_url: repoRes.data.html_url,
    clone_url: repoRes.data.clone_url,
    languages: langsRes.data,
    stargazers_count: repoRes.data.stargazers_count,
    forks_count: repoRes.data.forks_count,
    open_issues_count: repoRes.data.open_issues_count,
  };
}

/**
 * Download a GitHub repo as a ZIP via the GitHub API and extract it to destDir.
 * Does NOT require Git to be installed — uses the /zipball endpoint.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {string} destDir   - absolute path to extract repo into
 * @param {string} [token]   - optional GitHub PAT for private repos
 * @param {string} [branch]  - branch/ref to download (default: HEAD)
 */
export async function cloneRepo(owner, repo, destDir, token, branch = "HEAD") {
  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {};

  // GitHub API: GET /repos/{owner}/{repo}/zipball/{ref}
  // Returns a redirect to a pre-signed S3 URL — follow it
  console.log(`📥 Downloading ${owner}/${repo}@${branch} as ZIP…`);

  const response = await axios.get(
    `https://api.github.com/repos/${owner}/${repo}/zipball/${branch}`,
    {
      headers: {
        ...authHeaders,
        Accept: "application/vnd.github+json",
      },
      responseType: "arraybuffer",
      maxRedirects: 5,
    }
  );

  // Write the ZIP to a temp file
  fs.mkdirSync(destDir, { recursive: true });
  const tmpZip = path.join(destDir, "__repo.zip");
  fs.writeFileSync(tmpZip, Buffer.from(response.data));

  // Extract with adm-zip
  const zip = new AdmZip(tmpZip);
  const entries = zip.getEntries();

  // GitHub puts everything inside a top-level "<owner>-<repo>-<sha>/" folder
  // Strip that prefix so files land directly in destDir
  const topFolder = entries[0]?.entryName?.split("/")[0] ?? "";

  zip.getEntries().forEach((entry) => {
    if (entry.isDirectory) return;

    const relPath = topFolder
      ? entry.entryName.replace(topFolder + "/", "")
      : entry.entryName;

    if (!relPath) return;

    const outPath = path.join(destDir, relPath);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, entry.getData());
  });

  // Clean up temp zip
  fs.unlinkSync(tmpZip);

  console.log(`✅ Downloaded and extracted ${owner}/${repo} → ${destDir}`);
  return destDir;
}
