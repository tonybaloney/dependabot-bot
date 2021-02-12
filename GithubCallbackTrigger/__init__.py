import base64
import logging
import os

import azure.functions as func
import github
from github.Commit import Commit
from github.PullRequest import PullRequest
from github.Repository import Repository


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")
    req_body: dict = req.get_json()
    if "pull_request" not in req_body:
        return func.HttpResponse(f"Only care about PRs", status_code=200)
    repo = github.Github().create_from_raw_data(Repository, req_body["repository"])

    try:
        integration = github.GithubIntegration(
            integration_id=os.getenv("GITHUB_INTEGRATION_ID"),
            private_key=base64.b64decode(os.getenv("GITHUB_PRIVATE_KEY")),
        )
        installation = integration.get_installation(repo.owner.login, repo.name)

        connection = github.Github(integration.get_access_token(installation.id).token)
    except github.GithubException as exc:
        logging.error(exc.data)
        return func.HttpResponse(
            f"Failed to authenticate to the Github API, check that this app is installed",
            status_code=403,
        )

    pr = connection.create_from_raw_data(PullRequest, raw_data=req_body["pull_request"])

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

    logging.info(
        f"Received a request for package {package} from {version_from} to {version_to}"
    )

    try:
        logging.info(pr.url)
        pr.merge(
            "Dependabot-bot is merging PR for package {package} from {version_from} to {version_to}"
        )
    except github.GithubException as exc:
        logging.error(f"Failed to merge PR - {exc.status}, {exc.data}")
        return func.HttpResponse(
            f"Failed to merge PR - {exc.status}",
            status_code=500,
        )

    return func.HttpResponse(
        "Automatically merged PR",
        status_code=200,
    )
