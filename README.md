# 🛡️ SafeDroid: AI-Code-Sanitizer

![Build Status](https://img.shields.io/badge/CI%2FCD-passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-Android-blue)
![Security](https://img.shields.io/badge/Security-DevSecOps-red)

**SafeDroid** is an automated DevSecOps tool implemented as a Custom GitHub Action for Android projects. It is designed to proactively prevent critical security vulnerabilities and AI-generated "hallucinations" in modern development pipelines.

## 🚀 Key Features
* **Secret Leak Detection:** Scans the codebase for accidentally committed API keys, auth tokens, and passwords using advanced Regex patterns.
* **AI Hallucination Prevention:** Actively verifies Gradle dependencies (`build.gradle.kts`) by making HTTP head requests to Maven and Google repositories, ensuring that AI-generated libraries actually exist and are safe to pull.
* **Seamless CI/CD Integration:** Automatically blocks unsafe commits and pull requests before they merge into the production branch, protecting the software supply chain.

## 🛠️ How It Works
The core of the system is a Python-based static analyzer (`sanitizer.py`) orchestrated by a GitHub Action workflow (`action.yml`). Upon every code push, the sanitizer analyzes the repository. If a threat (e.g., a fake AI library or a leaked Google API Key) is detected, it immediately triggers a build failure with exit code 1, providing detailed logs for developers to fix the issue.
