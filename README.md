# 🛡️ SafeDroid: AI-Code-Sanitizer

![CI/CD passing](https://img.shields.io/badge/CI%2FCD-passing-brightgreen)
![platform Android](https://img.shields.io/badge/platform-Android-blue)
![Security](https://img.shields.io/badge/Security-darkgrey)
![DevSecOps](https://img.shields.io/badge/DevSecOps-red)

SafeDroid is an automated DevSecOps tool implemented as a Custom GitHub Action for Android projects. It is designed to proactively prevent critical security vulnerabilities and AI-generated "hallucinations" in modern development pipelines.

## 🚀 Key Features

*   **Secret Leak Detection**: Scans the codebase for accidentally committed API keys, auth tokens, and passwords using advanced Regex patterns.
*   **AI Hallucination Prevention**: Actively verifies Gradle dependencies (`build.gradle.kts`) by making HTTP head requests to Maven and Google repositories, ensuring that AI-generated libraries actually exist and are safe to pull.
*   **Seamless CI/CD Integration**: Automatically blocks unsafe commits and pull requests before they merge into the production branch, protecting the software supply chain.

## 🛠️ How It Works

The core of the system is a Python-based static analyzer (`sanitizer.py`) orchestrated by a GitHub Action workflow (`action.yml`). Upon every code push, the sanitizer analyzes the repository. If a threat (e.g., a fake AI library or a leaked Google API Key) is detected, it immediately triggers a build failure with exit code 1, providing detailed logs for developers to fix the issue.

## 📖 Usage

To start using SafeDroid, integrate it into your CI/CD pipeline by adding a new step to your existing GitHub Actions workflow file (for example, `.github/workflows/main.yml`).

```yaml
steps:
  # 1. Checkout your repository code
  - name: Checkout Code
    uses: actions/checkout@v4

  # 2. Run SafeDroid to scan for AI hallucinations and leaked secrets
  - name: Run SafeDroid Security Scan
    uses: zhenyasedoy-blip/SafeDroid@master
