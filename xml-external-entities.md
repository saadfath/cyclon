# XML External Entities (XXE)

## 1. Description

XML External Entity (XXE) is a security vulnerability that occurs when an application processes untrusted XML documents using an improperly configured XML parser that allows external entity references.

XML supports entities, which allow developers to define reusable values inside XML documents.

Some XML parsers can also resolve external entities by accessing external resources.

If external entity processing is enabled when handling untrusted XML, an attacker may cause the application to access unintended local or external resources.

Potential consequences include:

- Exposure of sensitive information.
- Unauthorized access to local resources.
- Server-side requests to unintended destinations.
- Information disclosure.
- Denial of Service.

### Example

Imagine an application that accepts XML documents from users and processes them using an XML parser.

If the parser allows external entity resolution, specially crafted XML may cause the application to retrieve resources that should not be accessible.

## 2. Common Causes

XXE vulnerabilities commonly occur when:

- Applications parse untrusted XML.
- External entity processing is enabled.
- DTD (Document Type Definition) processing is not restricted.
- XML parsers use insecure default configurations.
- Applications use outdated XML-processing libraries.
- XML validation allows unsafe external references.
- SOAP services process untrusted XML without appropriate restrictions.
- Developers assume that parsing XML is automatically safe.

## 3. Vulnerable Code Patterns

### Pattern 1: Unsafe XML parsing

Python example:

```python
from lxml import etree

def parse_xml(xml_data):
    parser = etree.XMLParser(
        resolve_entities=True
    )

    return etree.fromstring(xml_data, parser)
```

**Problem:**

The parser explicitly enables entity resolution.

When processing untrusted XML, external entity references may be resolved.

### Pattern 2: Parsing untrusted XML

```python
from lxml import etree

def process_document(user_xml):
    return etree.fromstring(user_xml)
```

**Problem:**

The application processes user-controlled XML without explicitly establishing whether its parser configuration safely handles DTDs and external entities.

This requires investigation of the parser's defaults and configuration.

## 4. Safer Implementation

A secure XML-processing implementation should:

- Disable external entity resolution.
- Disable external DTD loading when unnecessary.
- Restrict DTD processing.
- Use secure parser configurations.
- Keep XML-processing libraries updated.
- Apply input-size and processing limits.
- Avoid unnecessary XML features when processing untrusted documents.

### Example: Safer lxml configuration

```python
from lxml import etree

def parse_xml(xml_data):
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True
    )

    return etree.fromstring(xml_data, parser)
```

**Explanation:**

- `resolve_entities=False` prevents automatic entity substitution.
- `load_dtd=False` disables loading external DTDs.
- `no_network=True` prevents network access by the parser.

**Important:** Secure parser configuration must be evaluated against the application's requirements. Additional restrictions may be necessary depending on the XML library and how parsed documents are processed.

## 5. Detection Indicators

Cyclone should investigate the following patterns:

| Indicator | Description |
|---|---|
| Untrusted XML input | XML documents originate from users or external sources. |
| External entity resolution | The parser allows external entity processing. |
| DTD loading | External DTD loading is enabled. |
| Network-enabled parser | The parser can retrieve external resources. |
| Unsafe parser defaults | Security-sensitive options are not explicitly configured. |
| Outdated XML library | The application uses an outdated or vulnerable XML parser. |
| XML processing in SOAP | SOAP endpoints process untrusted XML without appropriate protections. |

These indicators require contextual analysis. XML parsing itself is not automatically vulnerable.

## 6. Python Functions and Libraries to Inspect

Cyclone should inspect common XML-processing libraries.

### lxml

```python
etree.fromstring()
etree.parse()
etree.XMLParser()
```

### xml.etree.ElementTree

```python
ET.fromstring()
ET.parse()
ET.XMLParser()
```

### xml.dom.minidom

```python
minidom.parse()
minidom.parseString()
```

### xml.sax

```python
xml.sax.parse()
xml.sax.make_parser()
```

### defusedxml

```python
defusedxml.ElementTree.fromstring()
defusedxml.ElementTree.parse()
```

The presence of these functions does not automatically indicate a vulnerability.

Cyclone must inspect parser configuration, library behavior, and the origin of the XML data.

## 7. Detection Logic for Cyclone

Cyclone should analyze XML-processing behavior using the following process:

1. Identify XML-processing libraries and parser creation functions.
2. Identify where XML documents originate.
3. Determine whether XML input is controlled by users or external systems.
4. Inspect parser configuration.
5. Check whether external entity resolution is enabled.
6. Check whether external DTD loading is enabled.
7. Inspect whether network access is permitted during parsing.
8. Identify outdated XML-processing dependencies.
9. Determine whether secure parsing configurations are actually applied.
10. Evaluate the possible impact of unsafe XML processing.

### Important distinction

Using an XML parser does not automatically indicate an XXE vulnerability.

For example, a parser configured to disable external entity resolution may safely process untrusted XML.

Cyclone must analyze both the input source and the parser's effective security configuration.

## 8. Severity Assessment

| Severity | Conditions |
|---|---|
| Critical | Confirmed XXE leads to severe compromise of sensitive systems or critical resources. |
| High | External entity processing exposes sensitive resources or enables significant server-side access. |
| Medium | Limited information disclosure or unintended external resource access is demonstrated. |
| Low | Restricted impact with additional security controls. |
| Informational | Suspicious XML parsing without sufficient evidence of unsafe entity resolution. |

Severity should consider:

- Whether untrusted XML is processed.
- Whether external entities are enabled.
- Whether local or external resources can be accessed.
- The sensitivity of accessible resources.
- Existing parser and network restrictions.

Do not assign severity based only on the presence of an XML parsing function.

## 9. Evidence Collection

For every potential XXE finding, Cyclone should collect:

- File name.
- Function name.
- Line number.
- XML-processing library.
- XML input source.
- Parser configuration.
- External entity resolution settings.
- DTD loading settings.
- Network access configuration.
- Dependency version.
- Relevant validation and security controls.

Cyclone must distinguish between confirmed evidence and assumptions.

## 10. Recommended Fixes

- Disable external entity resolution.
- Disable external DTD loading when unnecessary.
- Use secure XML parser configurations.
- Consider using `defusedxml` for untrusted XML processing.
- Keep XML-processing libraries updated.
- Apply XML document size limits.
- Restrict unnecessary network access.
- Avoid processing untrusted XML with insecure parser defaults.
- Review SOAP and other XML-based interfaces.
- Centralize secure XML parser configuration.

## 11. False Positives

Cyclone should avoid reporting every XML parser as vulnerable.

Possible false positives include:

- Parsers configured to disable external entity resolution.
- Applications using secure XML libraries.
- XML processing with trusted, fixed documents.
- Parsers with network access disabled.
- External entity functionality that is disabled through centralized configuration.

The scanner should inspect the effective parser configuration rather than relying exclusively on library names.

## 12. RAG Knowledge Summary

**Vulnerability:** XML External Entities (XXE)

**Category:** XML Security / Input Processing

**Affected Languages:** Python and other languages that process XML documents.

**Primary Risk:** Processing untrusted XML may allow unintended access to local or external resources.

**Common Sources:**
- User-uploaded XML files.
- XML API requests.
- SOAP messages.
- External XML documents.
- XML configuration imports.

**Common Sinks:**
- `lxml.etree.fromstring()`
- `lxml.etree.parse()`
- `xml.etree.ElementTree.fromstring()`
- `xml.dom.minidom.parseString()`
- `xml.sax.parse()`

**Detection Strategy:**

Identify untrusted XML input, trace it into XML parsers, inspect effective parser configuration, and determine whether external entity resolution or unsafe DTD processing is possible.

**Recommended Fix:**

Disable external entity resolution and unnecessary DTD loading, use secure XML parsers, and restrict unnecessary network access.

**Confidence Requirements:**

The presence of an XML parser alone is insufficient to confirm XXE. Cyclone must establish that untrusted XML reaches a parser configuration that permits unsafe external entity processing.

**Important:**

XXE and SSRF are different vulnerabilities, although XXE can sometimes lead to server-side requests.

- XXE originates from unsafe XML entity processing.
- SSRF originates from server-side requests to attacker-influenced destinations.

RAG should provide security knowledge and explain findings. The scanner's actual code analysis must independently establish whether the vulnerability exists.
