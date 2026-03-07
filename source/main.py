"""Main module for VPN config generator with refactored, streamlined logic."""

import os
import sys
import argparse

# Force unbuffered output for real-time streaming
os.environ['PYTHONUNBUFFERED'] = '1'
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from utils.logger import log, print_logs
from utils.download_xray import ensure_xray_installed
from processors.config_processor import process_all_configs
from utils.github_handler import GitHubHandler


def main(dry_run: bool = False, output_dir: str = "../githubmirror", skip_xray: bool = False, use_git: bool = False):
    """Main execution function with streamlined logic.
    
    Args:
        dry_run: Only download and save locally, don't upload/commit
        output_dir: Output directory for generated files
        skip_xray: Skip Xray-core download/use (TCP-only verification)
        use_git: Use git commands for committing instead of GitHub API
    """
    log("Starting VPN config generation...")
    
    # Download and install Xray-core if not present (unless skipped)
    if not skip_xray:
        xray_path = ensure_xray_installed()
        if xray_path:
            log(f"Xray-core ready: {xray_path}")
        else:
            log("Warning: Xray-core not installed. Will use TCP-only verification (slower).")

    # Process all configs following the new streamlined approach
    file_pairs = process_all_configs(output_dir)

    # Upload/commit files to GitHub if not in dry-run mode
    if not dry_run and file_pairs:
        if use_git:
            # Use git commands for committing (GitHub Actions mode)
            from utils.git_updater import GitUpdater
            try:
                updater = GitUpdater()
                success = updater.commit_and_push_files(file_pairs)
                if not success:
                    log("ERROR: Git update failed")
                    sys.exit(1)
            except Exception as e:
                log(f"ERROR: Git update failed: {e}")
                sys.exit(1)
        else:
            # Use GitHub API (local mode with token)
            github_handler = GitHubHandler()
            github_handler.upload_multiple_files(file_pairs)

    # Print logs
    print_logs()
    log("VPN config generation completed!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download configs and upload to GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Only download and save locally, don't upload to GitHub")
    parser.add_argument("--skip-xray", action="store_true", help="Skip Xray-core download/use (TCP-only verification)")
    parser.add_argument("--use-git", action="store_true", help="Use git commands for committing (for GitHub Actions)")
    args = parser.parse_args()

    main(dry_run=args.dry_run, skip_xray=args.skip_xray, use_git=args.use_git)