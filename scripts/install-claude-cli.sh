#!/usr/bin/env bash
set -euo pipefail

# Install Claude Code CLI globally via npm.
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Install Node.js 18+ first, then re-run this script."
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is not available. Reinstall Node.js with npm, then re-run this script."
  exit 1
fi

echo "Installing Claude CLI..."
npm install -g @anthropic-ai/claude-code

echo "\nClaude CLI installed."
echo "Run one of the following to authenticate:"
echo "  claude login"
echo "  claude auth login"

echo "\nTo verify installation:"
echo "  claude --version"
