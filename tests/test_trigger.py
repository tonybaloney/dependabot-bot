import azure.functions as func
from GithubCallbackTrigger import main


def test_pull_request():
    with open("tests/pull_request.json", "rb") as pr:
        req = func.HttpRequest(method="POST", url="https://testing.com", body=pr.read())
        result = main(req)
        assert result.status_code == 200
        assert result.get_body().decode("utf8") == "Not a bot PR"


def test_dependabot_pull_request():
    with open("tests/dependabot_pr.json", "rb") as pr:
        req = func.HttpRequest(method="POST", url="https://testing.com", body=pr.read())
        result = main(req)
        assert result.status_code == 200
        assert (
            result.get_body().decode("utf8")
            == "Received a request for package junit-jupiter from 5.7.0 to 5.7.1"
        )
