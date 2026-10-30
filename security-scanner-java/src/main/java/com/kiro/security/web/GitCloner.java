package com.kiro.security.web;

import java.io.File;
import java.nio.file.*;
import java.util.regex.*;

/**
 * Clones Git repositories (including GitLab/GitHub "tree" URLs with a branch)
 * into a local temp directory so the scanners can read the files.
 *
 * Relies on the system `git` command and the user's existing git credentials.
 */
public class GitCloner {

    public record RepoTarget(String cloneUrl, String branch, String repoName) {}

    /**
     * Determine if the given input looks like a Git URL (vs a local path).
     */
    public static boolean isGitUrl(String input) {
        if (input == null) return false;
        String s = input.trim();
        return s.startsWith("http://") || s.startsWith("https://")
                || s.startsWith("git@") || s.endsWith(".git");
    }

    /**
     * Normalize a browser/tree URL into a cloneable URL + branch.
     * Handles patterns like:
     *   https://host/group/project/-/tree/BRANCH?ref_type=heads   (GitLab)
     *   https://host/group/project/tree/BRANCH                     (GitHub)
     *   https://host/group/project.git
     *   https://host/group/project
     */
    public static RepoTarget parse(String rawUrl) {
        String url = rawUrl.trim();
        // strip query string
        int q = url.indexOf('?');
        if (q >= 0) url = url.substring(0, q);
        // strip trailing slash
        if (url.endsWith("/")) url = url.substring(0, url.length() - 1);

        String branch = null;

        // GitLab tree: .../-/tree/<branch>
        Matcher glTree = Pattern.compile("(.*?)/-/tree/([^/]+)").matcher(url);
        // GitHub tree: .../tree/<branch>
        Matcher ghTree = Pattern.compile("(.*?)/tree/([^/]+)").matcher(url);

        String base;
        if (glTree.matches()) {
            base = glTree.group(1);
            branch = glTree.group(2);
        } else if (ghTree.matches()) {
            base = ghTree.group(1);
            branch = ghTree.group(2);
        } else {
            base = url;
        }

        String cloneUrl = base.endsWith(".git") ? base : base + ".git";

        // Derive a repo name for the temp folder
        String repoName = base.replaceAll("\\.git$", "");
        int slash = repoName.lastIndexOf('/');
        repoName = slash >= 0 ? repoName.substring(slash + 1) : "repo";

        return new RepoTarget(cloneUrl, branch, repoName);
    }

    /**
     * Clone the repo into a temp directory and return the local path.
     * A shallow clone (--depth 1) is used for speed.
     */
    public static Path clone(RepoTarget target) throws Exception {
        Path tempDir = Files.createTempDirectory("secureforge-");
        Path dest = tempDir.resolve(target.repoName());

        java.util.List<String> cmd = new java.util.ArrayList<>();
        cmd.add("git");
        cmd.add("clone");
        cmd.add("--depth");
        cmd.add("1");
        if (target.branch() != null && !target.branch().isBlank()) {
            cmd.add("--branch");
            cmd.add(target.branch());
            cmd.add("--single-branch");
        }
        cmd.add(target.cloneUrl());
        cmd.add(dest.toString());

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        // non-interactive: fail fast rather than prompting for credentials
        pb.environment().put("GIT_TERMINAL_PROMPT", "0");

        System.out.println("  ⬇️  Cloning " + target.cloneUrl()
                + (target.branch() != null ? " (branch: " + target.branch() + ")" : "") + " ...");

        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes());
        int exit = p.waitFor();

        if (exit != 0) {
            throw new RuntimeException("Git clone failed (exit " + exit + "):\n" + output);
        }

        System.out.println("  ✓ Cloned to " + dest);
        return dest;
    }

    /**
     * Best-effort recursive delete of a cloned temp directory.
     */
    public static void cleanup(Path dir) {
        if (dir == null) return;
        try {
            Path root = dir.getParent() != null && dir.getParent().getFileName() != null
                    && dir.getParent().getFileName().toString().startsWith("secureforge-")
                    ? dir.getParent() : dir;
            Files.walk(root)
                 .sorted(java.util.Comparator.reverseOrder())
                 .map(Path::toFile)
                 .forEach(File::delete);
        } catch (Exception ignored) { }
    }
}
