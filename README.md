# API Security Testing Framework

A Python-based automated API security testing framework designed to detect common vulnerabilities such as broken authentication/authorization, injection flaws, security misconfigurations, missing rate limiting, and other OWASP API Security Top 10 risks. The framework leverages `requests` for HTTP interactions and `pytest` for validation.

## Features

- **OpenAPI/Swagger support**: Automatically generate test cases from API specifications.
- **Automated scanning**: Built-in scanners for authentication, authorization, injection, misconfiguration, rate limiting, and OWASP Top 10 indicators.
- **Detailed reporting**: Generate JSON reports summarizing results and risk levels.
- **CI/CD friendly**: Command-line interface suitable for pipeline integration.
- **Extensible architecture**: Easily add custom scanners or modify existing ones.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Run the CLI by providing an OpenAPI specification file and the base URL of the API:

```bash
python -m api_security_testing.runner path/to/openapi.json https://api.example.com \
  --privileged-token <ADMIN_TOKEN> \
  --unprivileged-token <USER_TOKEN> \
  --output security-report.json
```

The command prints a JSON report to stdout or saves it when `--output` is specified. The report includes a per-scan breakdown and aggregated statistics (total checks, pass/fail counts, and risk levels).

## Integrating with CI/CD

1. Add the framework and dependencies to your project's test requirements.
2. Generate or reference your OpenAPI specification during the pipeline run.
3. Execute the CLI as part of your CI job, for example:

```bash
python -m api_security_testing.runner openapi.yaml "$API_BASE_URL" --output api-security-report.json
```

4. Parse the JSON report to enforce quality gates or publish as a build artifact.

## Running Tests

```bash
pytest
```

The test suite includes fixtures for validating the OpenAPI loader, test case generation, and the orchestrated runner.

## Extending the Framework

- Implement additional scanners by subclassing `Scanner` in `api_security_testing/scanners/base.py`.
- Register custom scanners when instantiating `APISecurityTestRunner`.
- Enhance reporting by composing `ReportGenerator` instances or exporting in additional formats.

## License

This project is provided as-is without warranty. Adapt it to your organization's needs and security policies.
