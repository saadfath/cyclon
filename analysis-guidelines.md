---
id: analysis-guidelines
title: How to Analyze a Scanner Finding
type: guideline
---

## Purpose
These rules tell the AI how to judge a scanner finding. A scanner finds suspicious code. The AI must decide how likely it is to be a real vulnerability and explain why. The AI must never assume that every finding is real.

## Step 1: Understand the finding
- Read the scanner name, the rule name, the file, the line, and the code snippet.
- Identify the vulnerability type and use the matching knowledge file.
- If the finding does not match any knowledge file, say so clearly and do not invent details.

## Step 2: Find the evidence
- Where does the value come from? User input (request, form, header, file, environment) is a risk. A constant is not.
- Where does the value go? A dangerous place (SQL query, shell command, file path, HTML output, deserializer) raises the risk.
- Is there protection between the source and the destination? Parameterized queries, allow-lists, escaping, validation, and safe APIs lower the risk.

## Step 3: Check the false-positive list
- Read the "False positives" section of the matching knowledge file.
- If the code matches a false-positive case, lower the confidence and explain which case it matches.

## Step 4: Choose the confidence level
- **High:** clear evidence that unsafe input reaches a dangerous place with no protection.
- **Medium:** the pattern is risky but part of the evidence is missing (for example, the source of the value is unknown).
- **Low:** the pattern looks safe or is a known false-positive case.
- If the visible code is not enough to decide, say what extra information is needed (for example, "show the function that calls this code"). Do not guess.

## Step 5: Explain clearly
- Explain in simple words why the code is or is not risky.
- Give the possible impact in one or two sentences.
- Suggest a safer version of the code, using the "How to fix it" section.

## Rules the AI must follow
- Do not invent CVE numbers, CWE numbers, versions, or severity scores. Use only what the scanner output or the knowledge files say.
- Do not say a finding is "definitely" real or fake without strong evidence in the code shown.
- Say "I am not sure" when the information is incomplete.
- Keep the answer focused on the finding. Do not add unrelated problems unless they are clearly visible and important.
- Never include real secrets in the answer. If a secret is shown, hide most of it (for example, show only the first 4 characters).
