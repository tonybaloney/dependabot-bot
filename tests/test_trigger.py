import pytest
from pytest_mock import MockerFixture
import json
import os
import azure.functions as func
from GithubCallbackTrigger import main


@pytest.fixture(autouse=True)
def azure_function_environment_vars():
    with open("local.settings.json") as f:
        local_settings = json.load(f)
    for k, v in local_settings["Values"].items():
        os.environ[k] = v


def test_pull_request():
    with open("tests/pull_request.json", "rb") as pr:
        req = func.HttpRequest(method="POST", url="https://testing.com", body=pr.read())
        result = main(req)
        assert result.status_code == 200
        assert result.get_body().decode("utf8") == "Only care about bot PRs"


def test_dependabot_pull_request(mocker: MockerFixture):
    with open("tests/dependabot_pr.json", "rb") as pr:
        req = func.HttpRequest(method="POST", url="https://testing.com", body=pr.read())
        mocker.patch("github.PullRequest.PullRequest.merge")
        mocker.patch("github.PullRequest.PullRequest.create_review")
        result = main(req)
        assert result.status_code == 200
        assert result.get_body().decode("utf8") == "Automatically merged PR"


def test_dependabot_completed_check_run(mocker: MockerFixture):
    with open("tests/check_run.json", "rb") as pr:
        req = func.HttpRequest(method="POST", url="https://testing.com", body=pr.read())
        mocker.patch("github.PullRequest.PullRequest.merge")
        mocker.patch("github.PullRequest.PullRequest.create_review")
        result = main(req)
        assert result.status_code == 200
        assert result.get_body().decode("utf8") == "Automatically merged PR"


def test_dependabot_in_progress_check_run(mocker: MockerFixture):
    with open("tests/check_run.json", "rb") as pr:
        req = func.HttpRequest(method="POST", url="https://testing.com", body=pr.read())
        mocker.patch("github.PullRequest.PullRequest.merge")
        mocker.patch("github.PullRequest.PullRequest.create_review")
        result = main(req)
        assert result.status_code == 200
        assert result.get_body().decode("utf8") == "Automatically merged PR"
