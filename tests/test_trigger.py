import unittest.mock
import json
import os

import azure.functions as func
import github
import pytest
from pytest_mock import MockerFixture


from GithubCallbackTrigger import main, make_digest, get_details


@pytest.fixture(autouse=True)
def azure_function_environment_vars():
    with open("local.settings.json") as f:
        local_settings = json.load(f)
    for k, v in local_settings["Values"].items():
        os.environ[k] = v


def make_request(pr_file) -> func.HttpRequest:
    pr_body = pr_file.read()
    headers = {"X-Hub-Signature-256": make_digest(pr_body)}
    return func.HttpRequest(
        method="POST", url="https://testing.com", body=pr_body, headers=headers
    )


def test_pull_request():
    with open("tests/pull_request.json", "rb") as pr:
        result = main(make_request(pr))
        assert result.status_code == 200, result.get_body().decode("utf8")
        assert result.get_body().decode("utf8") == "Only care about bot PRs"


def test_dependabot_pull_request(mocker: MockerFixture):
    with open("tests/dependabot_pr.json", "rb") as pr:
        mocker.patch("github.PullRequest.PullRequest.merge")
        mocker.patch("github.PullRequest.PullRequest.create_review")
        result = main(make_request(pr))
        assert result.status_code == 200, result.get_body().decode("utf8")
        assert result.get_body().decode("utf8") == "Automatically merged PR"


def test_dependabot_pull_request_casing(mocker: MockerFixture):
    # Checks that its okay for casing to not match
    with open("tests/dependabot_pr_casing.json", "rb") as pr:
        mocker.patch("github.PullRequest.PullRequest.merge")
        mocker.patch("github.PullRequest.PullRequest.create_review")
        result = main(make_request(pr))
        assert result.status_code == 200
        assert result.get_body().decode("utf8") == "Automatically merged PR"


def test_dependabot_completed_check_run(mocker: MockerFixture):
    with open("tests/check_run.json", "rb") as pr:
        mocker.patch("github.PullRequest.PullRequest.merge")
        mocker.patch("github.PullRequest.PullRequest.create_review")
        mocker.patch("github.PullRequest.PullRequest.merged", False)
        result = main(make_request(pr))
        assert result.status_code == 200
        assert result.get_body().decode("utf8") == "Automatically merged PR"


def test_package_details():
    user_mock = unittest.mock.Mock(spec=github.NamedUser.NamedUser)
    user_mock.login = "pyup-bot"
    pr_mock = unittest.mock.Mock(spec=github.PullRequest.PullRequest)
    pr_mock.title = "Update tox to 3.21.4"
    pr_mock.user = user_mock
    package, version_to = get_details(pr_mock)
    assert package == "tox"
    assert version_to == "3.21.4"


def test_package_details_casing():
    user_mock = unittest.mock.Mock(spec=github.NamedUser.NamedUser)
    user_mock.login = "pyup-bot"
    pr_mock = unittest.mock.Mock(spec=github.PullRequest.PullRequest)
    pr_mock.title = "Update SQLAlchemy to 3.21.4"
    pr_mock.user = user_mock
    package, version_to = get_details(pr_mock)
    assert package == "sqlalchemy"
    assert version_to == "3.21.4"
