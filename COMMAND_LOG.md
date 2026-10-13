# Cloud Response Lab — Command Log

## Session 1: Environment and Git Setup

### 1. Check Python version

**Command**
```bash
python3.12 --version
```

**Purpose:** Confirm that Python 3.12 is installed.

**Why:** The project uses Python for response automation.

**Verification:** Python 3.12.10 was reported.

### 2. Create the virtual environment

**Command**
```bash
python3.12 -m venv .venv
```

**Purpose:** Create an isolated Python environment inside the project.

**Why:** Project dependencies stay separate from other Python projects on the Mac.

### 3. Activate the virtual environment

**Command**
```bash
source .venv/bin/activate
```

**Purpose:** Activate the project's environment in the current Terminal session.

**Verification:** The Terminal prompt displays `(.venv)`.

### 4. Verify the active Python interpreter

**Commands**
```bash
python --version
which python
```

**Purpose:** Confirm that commands use the project's Python environment.

**Verification:** Python 3.12.10 was reported, and the interpreter path was inside `cloud-response-lab/.venv/bin/python`.

### 5. Install project dependencies

**Command**
```bash
python -m pip install boto3 pytest
```

**Purpose:** Install the AWS SDK for Python (`boto3`) and the Python testing framework (`pytest`).

**Why:** `boto3` will support AWS automation; `pytest` will help test response functions.

**Verification:** `python -m pip show boto3 pytest` confirmed the packages were installed.

### 6. Run the starter Python program

**Command**
```bash
python hello_lab.py
```

**Purpose:** Confirm that Python can run a script in the project.

**Expected output**
```text
Cloud response lab is ready.
Python environment: operational
```

**Verification:** Both lines appeared in the Terminal.

### 7. Configure Git identity

**Commands**
```bash
git config --global user.name "cloudsec-dev"
git config --global user.email "YOUR_CONFIGURED_GIT_EMAIL"
```

**Purpose:** Configure the author information Git records with commits.

**Note:** The email placeholder represents the address configured locally. Do not replace it with a real email in this documentation unless you intentionally want that address recorded in the repository.

### 8. Initialize the Git repository

**Command**
```bash
git init
```

**Purpose:** Start tracking the project with Git.

**Why:** Git records changes over time and supports collaboration through commits and branches.

### 9. Ignore generated and sensitive files

**Command**
```bash
git check-ignore -v .venv/
```

**Purpose:** Verify that Git ignores the Python virtual environment.

**Verification:** Git identified the `.venv/` rule in `.gitignore`.

**Why:** The virtual environment contains generated files and installed packages that should not be committed.

### 10. Stage and commit the starter files

**Commands**
```bash
git add .gitignore hello_lab.py
git status
git commit -m "Initial lab setup"
git status
```

**Purpose:** Stage the starter files, inspect the proposed commit, save a version in Git, and verify the repository state.

**Verification:** Commit `bd242cf` was created with message `Initial lab setup`. The final status showed `On branch main` and `nothing to commit, working tree clean`.

## Key Concepts Learned

- **Terminal:** A text interface for running commands.
- **Virtual environment (`.venv`):** An isolated Python environment for this project.
- **Git repository:** The project and its tracked history.
- **Staging:** Selecting changes to include in the next commit.
- **Commit:** A saved snapshot of tracked changes.
- **Working tree:** The files and folders in the project directory.
- **Clean working tree:** No tracked changes are waiting to be committed.
- **`.gitignore`:** Rules telling Git which files to leave untracked.