# Learning log

Commands and steps we have learned, each with what it does and when to use it. 17 entries across 5 topics.

> Generated from learning-log.json. Add an entry in Discord (#learning-log) or with the console and this file regenerates; do not edit it by hand.

**Topics:** [Git](#git) (8) · [Python](#python) (3) · [Pytest](#pytest) (2) · [Pull request](#pull-request) (2) · [Tailscale](#tailscale) (2)

## Git

### `git status`

**What it does:** Shows which files you have changed, which are ready to be saved (staged), and which files git is not tracking yet.

**When to use it:** Before you add or commit, and any time you want to check where you are.

<sub>Added by assistant on 2026-10-15</sub>

### `git switch -c my-change`

**What it does:** Creates a new branch called my-change and moves you onto it, so your work stays separate from the main version.

**When to use it:** At the start of any new piece of work, before you edit files. Pick a short name that says what the change is.

<sub>Added by assistant on 2026-10-15</sub>

### `git add .`

**What it does:** Marks every changed file to be included in your next commit. The dot means "everything in this folder".

**When to use it:** After git status shows only the changes you expect. To pick one file instead, use git add followed by the file name.

<sub>Added by assistant on 2026-10-15</sub>

### `git commit -m "Explain the change"`

**What it does:** Saves the staged changes as one snapshot in your local history, with a short message saying what and why.

**When to use it:** When a small, working piece is done. Several small commits are easier to review than one huge one.

<sub>Added by assistant on 2026-10-15</sub>

### `git push -u origin my-change`

**What it does:** Sends your branch to GitHub. The -u part remembers the link, so next time plain git push is enough.

**When to use it:** The first time you push a new branch, so it shows up on GitHub and can become a pull request.

<sub>Added by assistant on 2026-10-15</sub>

### `git pull`

**What it does:** Downloads new commits from GitHub and merges them into the branch you are on.

**When to use it:** Before you start work for the day, and whenever someone says they pushed something you need.

<sub>Added by assistant on 2026-10-15</sub>

### `git log --oneline -5`

**What it does:** Lists the last five commits, one line each, newest first.

**When to use it:** To remember what you did last, or to find the commit someone is asking about.

<sub>Added by assistant on 2026-10-15</sub>

### `git diff`

**What it does:** Shows the lines you added and removed in files that are not staged yet. Plus means added, minus means removed.

**When to use it:** After editing and before git add, to review your own work. Use git diff --staged to review what is about to be committed.

<sub>Added by owner on 2026-10-15</sub>

## Python

### `python3 -m venv .venv`

**What it does:** Creates a folder called .venv holding its own copy of Python and its own packages, so this project’s installs cannot break other projects.

**When to use it:** Once per project, the first time you set it up.

<sub>Added by assistant on 2026-10-15</sub>

### `source .venv/bin/activate`

**What it does:** Makes your terminal use the Python and packages inside .venv. Your prompt shows (.venv) while it is on. Type deactivate to switch it off.

**When to use it:** Every time you open a new terminal to work on the project, before running its code or tests.

<sub>Added by assistant on 2026-10-15</sub>

### `pip install -r requirements.txt`

**What it does:** Reads the project’s list of required packages and installs them into the active toolbox.

**When to use it:** Right after activating a fresh .venv, and again whenever requirements.txt changes.

<sub>Added by assistant on 2026-10-15</sub>

## Pytest

### `python3 -m pytest -q`

**What it does:** Runs every automated test in the project and prints a short summary. -q means quiet: fewer lines, same result.

**When to use it:** Before you commit and before you open a pull request, to prove you did not break anything.

<sub>Added by assistant on 2026-10-15</sub>

### `python3 -m pytest -k lookback -x`

**What it does:** -k picks only tests whose name contains the word you give (here "lookback"). -x stops at the first failing test so you can fix it before going on.

**When to use it:** When one thing is failing and you want a fast loop on just that test.

<sub>Added by assistant on 2026-10-15</sub>

## Pull request

### `Open a pull request on GitHub (Compare & pull request)`

**What it does:** A pull request asks the team to look at your branch and, once approved, merge it into main. GitHub shows the changes, the checks and the conversation in one place.

**When to use it:** After you have pushed your branch and the tests pass. Never merge your own work without the owner’s say-so.

<sub>Added by assistant on 2026-10-15</sub>

### `git diff main...HEAD --stat`

**What it does:** Lists the files your branch changed compared with main, with a count of added and removed lines.

**When to use it:** Just before opening a pull request, to check you are not sending anything you did not mean to.

<sub>Added by assistant on 2026-10-15</sub>

## Tailscale

### `tailscale status`

**What it does:** Lists the devices on our private network (the tailnet) and whether each is online.

**When to use it:** Before opening the Kibana or Shuffle links. If you are not connected, those pages will not load.

<sub>Added by assistant on 2026-10-15</sub>

### `tailscale ip -4`

**What it does:** Prints this device’s private tailnet address.

**When to use it:** When someone needs to reach your machine over the tailnet. Keep the address out of chat and public repos.

<sub>Added by assistant on 2026-10-15</sub>
