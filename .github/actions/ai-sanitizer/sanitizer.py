import os
import sys
import re
import urllib.request
import urllib.error

# Regular expressions for secret scanning
SECRET_PATTERNS = {
    "Google API Key": r'(AIzaSy[A-Za-z0-9\-_]{33})',
    "OpenAI API Key": r'(sk-[a-zA-Z0-9]{48})',
    "Keystore Password / Firebase Token": r'(?i)(?:password|token|secret)[\s]*[=:]\s*[\'"]([^\'"]{8,})[\'"]'
}

# Regular expression for finding Gradle dependencies
DEPENDENCY_PATTERN = re.compile(
    r'(?:implementation|api|compileOnly|kapt|ksp|testImplementation|androidTestImplementation)\s*(?:\(\s*)?[\'"]([^:\'"]+):([^:\'"]+):([^:\'"]+)[\'"](?:\s*\))?'
)

def mask_secret(secret_string):
    """Masks a secret, leaving only the first 3 characters visible."""
    if len(secret_string) <= 3:
        return "***"
    return secret_string[:3] + "*" * (len(secret_string) - 3)

def scan_for_secrets(directory):
    """Scans .kt and .java files for leaked secrets."""
    print("=== RUNNING CHECK 1: SECRET LEAKS SCAN ===")
    found_secrets = False

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.kt') or file.endswith('.java'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line_number, line in enumerate(lines, 1):
                            for secret_name, pattern in SECRET_PATTERNS.items():
                                matches = re.findall(pattern, line)
                                for match in matches:
                                    found_secrets = True
                                    masked = mask_secret(match)
                                    print(f"[DANGER] Found {secret_name} in file {filepath}:{line_number}")
                                    print(f" -> Value: {masked}")
                except Exception as e:
                    print(f"Error reading file {filepath}: {e}")

    return found_secrets

def check_dependency_exists(group, artifact, version):
    """Checks if a dependency exists in Maven Central or Google Maven."""
    group_path = group.replace('.', '/')
    pom_file = f"{artifact}-{version}.pom"

    urls_to_check = [
        f"https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{pom_file}",
        f"https://maven.google.com/{group_path}/{artifact}/{version}/{pom_file}"
    ]

    for url in urls_to_check:
        try:
            req = urllib.request.Request(url, method='HEAD')
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    return True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            return True
        except Exception:
            return True

    return False

def scan_for_hallucinated_dependencies(directory):
    """Scans build.gradle and build.gradle.kts files for hallucinated dependencies."""
    print("\n=== RUNNING CHECK 2: AI HALLUCINATIONS SCAN (DEPENDENCIES) ===")
    hallucinations_found = False

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == 'build.gradle' or file == 'build.gradle.kts':
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line_number, line in enumerate(lines, 1):
                            matches = DEPENDENCY_PATTERN.findall(line)
                            for match in matches:
                                group, artifact, version = match
                                print(f"Checking: {group}:{artifact}:{version}...", end=" ")

                                if '$' in version or version.startswith('libs.'):
                                    print("SKIPPED (Dynamic version)")
                                    continue

                                is_valid = check_dependency_exists(group, artifact, version)
                                if not is_valid:
                                    print("NOT FOUND!")
                                    print(f"[HALLUCINATION] Fake dependency detected in {filepath}:{line_number}")
                                    print(f" -> {group}:{artifact}:{version}")
                                    hallucinations_found = True
                                else:
                                    print("OK")
                except Exception as e:
                    print(f"Error reading file {filepath}: {e}")

    return hallucinations_found

def main():
    if len(sys.argv) > 1:
        scan_dir = sys.argv[1]
    else:
        scan_dir = "."

    print(f"Starting AI-Code-Sanitizer in directory: {os.path.abspath(scan_dir)}\n")

    secrets_leaked = scan_for_secrets(scan_dir)
    hallucinations_present = scan_for_hallucinated_dependencies(scan_dir)

    print("\n=== SCAN SUMMARY ===")
    if secrets_leaked or hallucinations_present:
        print("[CRITICAL ERROR] Code is insecure. Leaked secrets or hallucinated dependencies detected.")
        sys.exit(1)
    else:
        print("[SUCCESS] All checks passed. No hallucinations or leaks found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
