import logging
import re
from github.PullRequest import PullRequest
from github.CheckRun import CheckRun
from github.Commit import Commit
import github
import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")
    req_body: dict = req.get_json()
    if "pull_request" not in req_body:
        return func.HttpResponse(f"Unsupported operation", status_code=405)
    logging.info(req.get_body().decode(encoding="utf8"))
    pr = github.Github().create_from_raw_data(
        PullRequest, raw_data=req_body["pull_request"]
    )
    # Only care about PRs from bots
    if pr.user.type != "Bot":
        return func.HttpResponse(f"Not a bot PR", status_code=200)
    # Only care about PRs from dependabot or the preview version
    if "dependabot" not in pr.user.login:
        return func.HttpResponse(f"Not dependabot", status_code=200)

    if not pr.mergeable or pr.merged:
        return func.HttpResponse(
            f"PR cannot be merged automatically, or it is already merged.",
            status_code=200,
        )

    # Determine which package is being bumped.
    _, package, _, version_from, _, version_to = pr.title.split(" ", 6)

    # Get the status of the PR

    # Get last commit
    if pr.commits > 1:
        logging.info("Warning: This PR somehow has lots of commits?")

    commit: Commit = list(pr.get_commits())[0]
    any_failed = any(run.conclusion == "failure" for run in commit.get_check_runs())
    if any_failed:
        return func.HttpResponse(
            f"PR cannot be merged automatically because one of the checks failed.",
            status_code=200,
        )

    return func.HttpResponse(
        f"Received a request for package {package} from {version_from} to {version_to}",
        status_code=200,
    )
