#!/bin/bash

# NOSP vFINAL APEX - Automated GitHub Deployment Script
# This script initializes git, stages files, commits, and pushes to GitHub

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "═══════════════════════════════════════════════════════════"
echo "  NOSP vFINAL APEX - Automated GitHub Deployment"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}ERROR: Git is not installed!${NC}"
    echo "Please install Git from https://git-scm.com/downloads"
    exit 1
fi

echo -e "${GREEN}✓ Git is installed${NC}"

# Configuration
REPO_URL="https://github.com/4fqr/nosp.git"
BRANCH="main"
COMMIT_MESSAGE="NOSP vFINAL APEX - Automated Deployment $(date '+%Y-%m-%d %H:%M:%S')"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo -e "${YELLOW}⚠ Not a git repository. Initializing...${NC}"
    git init
    echo -e "${GREEN}✓ Git repository initialized${NC}"
else
    echo -e "${GREEN}✓ Already a git repository${NC}"
fi

# Check if remote origin exists
if git remote | grep -q "^origin$"; then
    echo -e "${YELLOW}⚠ Remote 'origin' already exists${NC}"
    CURRENT_REMOTE=$(git remote get-url origin)
    echo "Current remote: $CURRENT_REMOTE"
    
    # Ask if user wants to change it
    read -p "Do you want to change it to $REPO_URL? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git remote set-url origin "$REPO_URL"
        echo -e "${GREEN}✓ Remote origin updated${NC}"
    fi
else
    echo -e "${YELLOW}Adding remote origin...${NC}"
    git remote add origin "$REPO_URL"
    echo -e "${GREEN}✓ Remote origin added: $REPO_URL${NC}"
fi

# Create .gitignore if it doesn't exist
if [ ! -f ".gitignore" ]; then
    echo -e "${YELLOW}Creating .gitignore...${NC}"
    cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
*.egg-info/
dist/
build/
*.egg

# Rust
target/
Cargo.lock
*.pdb

# NOSP specific
nosp_data/
session.json
events.log
*.db
quarantine/
models/
plugins/*.pyc

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
EOF
    echo -e "${GREEN}✓ .gitignore created${NC}"
fi

# Stage all files
echo -e "${YELLOW}Staging files...${NC}"
git add .

# Show what will be committed
echo -e "${YELLOW}Files to be committed:${NC}"
git status --short

# Ask for confirmation
echo ""
read -p "Do you want to proceed with commit and push? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Deployment cancelled by user${NC}"
    exit 0
fi

# Commit
echo -e "${YELLOW}Committing changes...${NC}"
if git diff --cached --quiet; then
    echo -e "${YELLOW}⚠ No changes to commit${NC}"
else
    git commit -m "$COMMIT_MESSAGE"
    echo -e "${GREEN}✓ Changes committed${NC}"
fi

# Check if branch exists remotely
echo -e "${YELLOW}Checking remote branch...${NC}"
git fetch origin $BRANCH 2>/dev/null || true

if git ls-remote --heads origin $BRANCH | grep -q $BRANCH; then
    echo -e "${YELLOW}⚠ Remote branch '$BRANCH' exists. Pulling latest changes...${NC}"
    git pull origin $BRANCH --rebase || {
        echo -e "${RED}ERROR: Merge conflict detected!${NC}"
        echo "Please resolve conflicts manually and run:"
        echo "  git rebase --continue"
        echo "  git push origin $BRANCH"
        exit 1
    }
fi

# Push to GitHub
echo -e "${YELLOW}Pushing to GitHub...${NC}"
git push -u origin $BRANCH

if [ $? -eq 0 ]; then
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✓ DEPLOYMENT SUCCESSFUL!"
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "Repository URL: $REPO_URL"
    echo "Branch: $BRANCH"
    echo "Commit: $COMMIT_MESSAGE"
    echo ""
    echo "View your repository at:"
    echo "  https://github.com/4fqr/nosp"
else
    echo -e "${RED}"
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✗ DEPLOYMENT FAILED!"
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "Please check the error messages above."
    echo "You may need to:"
    echo "  1. Configure your GitHub credentials"
    echo "  2. Create the repository first on GitHub"
    echo "  3. Check network connection"
    exit 1
fi
