import base64
import logging
import os
from github.ContentFile import ContentFile
import hmac
import hashlib
import yaml
import azure.functions as func
import github
from github.Commit import Commit
from github.PullRequest import PullRequest
from github.Repository import Repository

SUPPORTED_BOTS = {
    "dependabot",
    "dependabot[bot]",
    "dependabot-preview",
    "dependabot-preview[bot]",
    "pyup-bot",
}


def bot(user):
    # pyup.io
    if user.login == "pyup-bot":
        return True

    # dependabot or the preview version
    if "dependabot" in user.login and user.type == "Bot":
        return True

    return False


def get_details(pr):
    package = None
    version_to = None

    # pyup.io
    if pr.user.login == "pyup-bot":
        _, package, _, version_to = pr.title.split(" ", 4)

    # dependabot or the preview version
    if "dependabot" in pr.user.login and pr.user.type == "Bot":
        _, package, _, _, _, version_to = pr.title.split(" ", 6)

    if package:
        package = package.lower()

    return package, version_to


def make_digest(body:bytes) -> str:
    return (
        "sha256="
        + hmac.new(
            os.getenv("GITHUB_HOOK_TOKEN").encode(),
            msg=body,
            digestmod=hashlib.sha256,
        ).hexdigest()
    )

def main(req: func.HttpRequest) -> func.HttpResponse:
    if "X-Hub-Signature-256" not in req.headers:
        return func.HttpResponse("Go away", status_code=403)

    digest = make_digest(req.get_body())

    if not hmac.compare_digest(req.headers["X-Hub-Signature-256"], digest):
        return func.HttpResponse("Go away", status_code=403)

    logging.info("Python HTTP trigger function processed a request.")
    req_body: dict = req.get_json()
    if "pull_request" not in req_body and "check_run" not in req_body:
        return func.HttpResponse("Only care about PRs", status_code=200)
    if (
        "pull_request" in req_body
        and req_body["pull_request"]["user"]["login"] not in SUPPORTED_BOTS
    ):
        return func.HttpResponse("Only care about bot PRs", status_code=200)
    if "check_run" in req_body:
        if req_body["action"] != "completed":
            return func.HttpResponse("Only care about PRs", status_code=200)
        if (
            "pull_requests" not in req_body["check_run"]
            or len(req_body["check_run"]["pull_requests"]) != 1
        ):
            return func.HttpResponse("Only care about PRs", status_code=200)

    try:
        integration = github.GithubIntegration(
            integration_id=os.getenv("GITHUB_INTEGRATION_ID"),
            private_key=base64.b64decode(os.getenv("GITHUB_PRIVATE_KEY")),
        )
        installation_id = req_body["installation"]["id"]
        connection = github.Github(integration.get_access_token(installation_id).token)
    except github.GithubException as exc:
        logging.error(exc.data)
        return func.HttpResponse(
            "Failed to authenticate to the Github API, check that this app is installed",
            status_code=403,
        )

    repo = connection.create_from_raw_data(Repository, raw_data=req_body["repository"])
    if "pull_request" in req_body:
        pr: PullRequest = connection.create_from_raw_data(
            PullRequest, raw_data=req_body["pull_request"]
        )
    elif "check_run" in req_body:
        pr: PullRequest = repo.get_pull(
            req_body["check_run"]["pull_requests"][0]["number"]
        )

    if not bot(pr.user):
        return func.HttpResponse(
            "Not for a bot.",
            status_code=200,
        )

    if pr.mergeable is False or pr.merged:
        return func.HttpResponse(
            "PR cannot be merged automatically, or it is already merged.",
            status_code=200,
        )

    # Determine which package is being bumped.
    package, version_to = get_details(pr)

    if not package or not version_to:
        return func.HttpResponse(
            "PR not from a bot?",
            status_code=200,
        )

    # Get the safelist
    try:
        config_file: ContentFile = repo.get_contents(".github/dependabot-bot.yml")
    except github.UnknownObjectException:
        try:
            config_file: ContentFile = repo.get_contents(".github/dependabot-bot.yaml")
        except github.UnknownObjectException:
            logging.info("Can't find configuration file")
            return func.HttpResponse(
                "PR cannot be merged automatically, this repo doesn't have a config file.",
                status_code=200,
            )

    try:
        config = yaml.safe_load(config_file.decoded_content)
    except Exception as exc:
        logging.error(f"Can't load configuration file {exc}")
        return func.HttpResponse(
            "PR cannot be merged automatically, the config file is invalid.",
            status_code=406,
        )

    if "safe" not in config:
        logging.error("Config missing safe list")
        return func.HttpResponse(
            "PR cannot be merged automatically, the config file is invalid because its missing the 'safe' list.",
            status_code=406,
        )

    if package not in [pkg.lower() for pkg in config["safe"]]:
        logging.info("Package not on safe list")
        return func.HttpResponse(
            "This package is not on the safe list, ignoring.",
            status_code=200,
        )

    # Get last commit
    if pr.commits > 1:
        logging.info("Warning: This PR somehow has lots of commits?")

    commit: Commit = list(pr.get_commits())[-1]

    any_failed = any(run.conclusion == "failure" for run in commit.get_check_runs())
    if any_failed:
        return func.HttpResponse(
            "PR cannot be merged automatically because one of the checks failed.",
            status_code=200,
        )

    logging.info(f"Received a request for package {package} to {version_to}")

    try:
        if not any(review.user == "depend-a-bot-bot" for review in pr.get_reviews()):
            pr.create_review(
                body=f"This PR looks good to merge automatically because {package} is on the safe-list for this repository.",
                commit=commit,
                event="APPROVE",
            )
        pr.merge(f"Dependabot-bot is merging PR for package {package} to {version_to}")
        logging.info(f"Merged {pr.url}")
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
