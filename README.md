# Introduction

**Fuzzinator5000** is a powerful Burp Suite extension for advanced fuzzing and request comparison workflows. It enables security testers to efficiently fuzz HTTP requests with custom payloads while simultaneously testing dependent requests and comparing responses.

**Key Features:**
* Dual Request Testing: Run two HTTP requests side-by-side with independent editors and viewers
* Intelligent Fuzzing Engine: Replace markers in requests with payloads from custom wordlists
* Sequential & Multithreaded Modes: Choose between sequential payload execution or parallel processing
* Auto-Chain Requests: Automatically execute a second request after each fuzzed request (e.g., for dependency chains)
* Response Comparison: Side-by-side response viewer with diff highlighting to identify anomalies
* Results Dashboard: Comprehensive table tracking all fuzzing iterations with payload, status, and response sizes
* Response Filtering: Filter results by response size to quickly identify interesting variations
* Direct Request/Response Viewing: Click any result to inspect full request/response details

**Use Cases:**
* Testing parameter injection vulnerabilities across interdependent endpoints
* Fuzzing APIs that require chained requests
* Identifying response anomalies when payloads are varied
* Comparing response differences across multiple payload variations
* Efficient wordlist-based security testing workflows

### Building the JAR file

To build the JAR file, run the following command in the root directory of this project:

* For UNIX-based systems: `./gradlew jar`
* For Windows systems: `gradlew jar`

If successful, the JAR file is saved to `<project_root_directory>/build/libs/<project_name>.jar`. If the build fails, errors are shown in the console. By default, the project name is `extension-template-project`. You can change this in the [settings.gradle.kts](./settings.gradle.kts) file.


## Loading the JAR file into Burp

To load the JAR file into Burp:

1. In Burp, go to **Extensions > Installed**.
2. Click **Add**.
3. Under **Extension details**, click **Select file**.
4. Select the JAR file you just built, then click **Open**.
5. [Optional] Under **Standard output** and **Standard error**, choose where to save output and error messages.
6. Click **Next**. The extension is loaded into Burp.
7. Review any messages displayed in the **Output** and **Errors** tabs.
8. Click **Close**.

Your extension is loaded and listed in the **Burp extensions** table.

### Reloading the JAR file in Burp

If you make changes to the code, you must rebuild the JAR file and reload your extension in Burp for the changes to take effect.

To rebuild the JAR file, follow the steps for [building the JAR file](#building-the-jar-file).

To quickly reload your extension in Burp:

1. In Burp, go to **Extensions > Installed**.
2. Hold `Ctrl` or `⌘`, and select the **Loaded** checkbox next to your extension.

---

# Common Errors

if you experience errors such as:

```
java.lang.IllegalArgumentException: HTTP service cannot be null
```

Make sure you have used the proper way to send a request to the extension. Right click in "targets" and send from there, dont manually insert the request.

# Changelog
- 1.0.0 - Release
