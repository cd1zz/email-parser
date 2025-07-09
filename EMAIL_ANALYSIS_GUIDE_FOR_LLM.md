# Email Analysis Guide: Understanding JSON Structure for Security Analysis

---

## Overview

This document explains how to analyze the JSON output from the email parser to identify potential security threats, phishing attempts, and malicious content. The parser is designed to handle complex, multi-layered email structures that are commonly used in sophisticated attacks.

### Core Security Principle
**Modern phishing attacks rarely arrive as simple, single-layer emails.** Instead, they are often embedded within legitimate-looking "carrier" emails that serve as delivery mechanisms. Understanding this layered approach is crucial for effective threat analysis.

---

## Email Layer Architecture

### The Carrier vs. Payload Concept

#### **Carrier Emails** (Outer Layers)
- **Purpose**: Legitimate-looking delivery mechanism
- **Characteristics**:
  - Often forwarded messages from known contacts
  - Security notifications or reports
  - Internal company communications
  - Automated system messages
- **Analysis Focus**: Minimal - these are usually legitimate transport layers
- **Example Scenarios**:
  - "FW: Phishing Email Analysis" (security team forwarding suspicious content)
  - "Incident Report: Suspicious Email Detected" 
  - "User Reported Phishing Attempt"

#### **Payload Emails** (Inner Layers)
- **Purpose**: Contains the actual malicious content
- **Characteristics**:
  - Embedded as attachments (.eml, .msg files)
  - Often base64-encoded within message bodies
  - May have multiple nested layers for evasion
- **Analysis Focus**: Primary scrutiny should be applied here
- **Red Flags**:
  - Mismatched sender domains
  - Urgent action requests
  - Suspicious URLs or attachments
  - Social engineering tactics

---

## JSON Structure Breakdown

### Top-Level Structure
```json
{
  "status": "success|failed",
  "detected_format": "eml|msg|mbox",
  "structure": {
    "metadata": { /* parsing metadata */ },
    "email": { /* root email object */ },
    "summary": { /* aggregated analysis */ }
  }
}
```

### Email Object Structure (Recursive)
Each email layer follows this structure:

```json
{
  "level": 0,  // Depth indicator (0=outermost, higher=deeper)
  "headers": {
    "from": "sender@domain.com",
    "to": "recipient@domain.com", 
    "subject": "Email subject",
    "date": "timestamp",
    "message_id": "unique-identifier"
  },
  "body": {
    "text": "Plain text content",
    "html": "HTML content (truncated for display)",
    "has_html": true
  },
  "attachments": [
    {
      "name": "attachment.eml",
      "type": "email|document|image",
      "contains_email": true,
      "nested_email": { /* recursive email structure */ },
      "document_urls": ["extracted URLs from documents"]
    }
  ],
  "nested_emails": [
    { /* recursive email structures */ }
  ],
  "urls": ["extracted URLs from body"],
  "id": "nested_0_0" // Unique identifier for nested emails
}
```

### Key Security Fields

#### **Level Field**
- **Purpose**: Indicates nesting depth
- **Security Significance**: 
  - Level 0-1: Usually carrier emails (low threat)
  - Level 2+: Payload emails (high scrutiny required)
  - Deep nesting (level 4+) may indicate evasion attempts

#### **Headers Analysis**
- **From/To Mismatch**: Sender doesn't match expected domain
- **Subject Manipulation**: Generic subjects hiding specific threats
- **Date Anomalies**: Future dates, inconsistent timestamps

#### **URL Arrays**
- **Body URLs**: Direct links in email text
- **Document URLs**: Links extracted from PDF/Office attachments
- **Nested Propagation**: URLs from deeper layers bubble up

---

## Security Analysis Methodology

### Step 1: Identify Email Architecture
```json
// Example: 3-layer structure analysis
{
  "structure": {
    "metadata": {
      "total_depth": 2,     // Maximum nesting level
      "total_emails": 3,    // Total email objects
      "total_attachments": 2
    }
  }
}
```

**Analysis Questions:**
- How many layers exist? (more layers = higher suspicion)
- What's the carrier-to-payload ratio?
- Are there unnecessary forwarding chains?

### Step 2: Trace the Email Chain
Follow the nesting structure from outermost to innermost:

1. **Level 0** (Root): Usually legitimate forwarding
2. **Level 1** (First nested): Often security reports or forwards
3. **Level 2+** (Deep nested): **PRIMARY ANALYSIS TARGET**

### Step 3: Analyze Each Layer's Intent

#### **Carrier Layer Analysis** (Levels 0-1)
- Verify sender legitimacy
- Check if forwarding is expected
- Look for security team notifications

#### **Payload Layer Analysis** (Levels 2+)
- **Headers**: Domain reputation, sender verification
- **Body Content**: Social engineering tactics, urgency language
- **URLs**: Destination analysis, shortener detection
- **Attachments**: File type validation, embedded content

### Step 4: Cross-Layer Correlation
Look for inconsistencies across layers:
- **Domain Hopping**: Different domains at each level
- **Content Mismatch**: Carrier claims vs. payload reality
- **URL Injection**: Malicious URLs only in deep layers

---

## Threat Pattern Recognition

### Pattern 1: Legitimate Security Report Wrapper
```json
{
  "level": 0,
  "headers": {
    "from": "security@company.com",
    "subject": "FW: Phishing Email Analysis"
  },
  "nested_emails": [
    {
      "level": 1,
      "headers": {
        "from": "analyst@company.com", 
        "subject": "Phishing: [THREAT ID] Analysis"
      },
      "nested_emails": [
        {
          "level": 2,  // ← ACTUAL THREAT STARTS HERE
          "headers": {
            "from": "attacker@malicious.com",
            "subject": "Urgent: Account Verification Required"
          },
          "urls": ["https://malicious-site.com/phish"]
        }
      ]
    }
  ]
}
```

**Analysis Focus**: Level 2 email contains the actual phishing attempt.

### Pattern 2: Document-Embedded Threats
```json
{
  "level": 1,
  "attachments": [
    {
      "name": "Invoice.pdf",
      "type": "document",
      "document_urls": [
        "https://legitimate-company.com",  // Benign
        "https://bit.ly/suspicious123"    // ← SUSPICIOUS
      ]
    }
  ]
}
```

**Red Flag**: Mixed legitimate and suspicious URLs in same document.

### Pattern 3: Progressive Trust Erosion
```json
{
  "summary": {
    "urls": {
      "by_domain": {
        "microsoft.com": ["https://microsoft.com/legitimate"],     // Level 0
        "bit.ly": ["https://bit.ly/shortened"],                   // Level 1  
        "random-domain.tk": ["https://random-domain.tk/malware"] // Level 2
      }
    }
  }
}
```

**Pattern**: URL trustworthiness decreases with nesting depth.

---

## Practical Analysis Examples

### Example 1: Proofpoint-Wrapped Phishing
```json
{
  "structure": {
    "email": {
      "level": 0,
      "headers": {
        "from": "security@company.com",
        "subject": "FW: Phishing Email Analysis"
      },
      "body": {
        "text": "Falsely flagged as legitimate..."
      },
      "nested_emails": [
        {
          "level": 1,
          "headers": {
            "from": "phishing-detector@company.com",
            "subject": "Phishing: [ID] Analysis Report"
          },
          "nested_emails": [
            {
              "level": 2,
              "headers": {
                "from": "Agreement: <andyn@dm.bbb.org>",
                "subject": "Review Contract Agreement now"
              },
              "body": {
                "text": "Your completed document is ready to review VIEW DOCUMENT HERE"
              },
              "urls": [],
              "id": "nested_1_0"
            }
          ]
        }
      ]
    }
  }
}
```

**Analysis:**
- **Carrier** (Levels 0-1): Legitimate security analysis
- **Payload** (Level 2): Suspicious generic sender, action-oriented language
- **Threat Assessment**: Medium - social engineering attempt wrapped in security report

### Example 2: Multi-Document URL Injection
```json
{
  "structure": {
    "email": {
      "level": 1,
      "attachments": [
        {
          "name": "Statement-02-03-2025.xlsx",
          "document_urls": [
            "https://1drv.ms/f/s!AtZJVMbRvgyjgQXyC7pOVtCcGRfF?e=OoLsjo",
            "https://www.w3.org/1999/02/22-rdf-syntax-ns"
          ]
        }
      ],
      "urls": ["https://aka.ms/LearnAboutSenderIdentification"]
    },
    "summary": {
      "urls": {
        "total_count": 4,
        "by_domain": {
          "1drv.ms": ["OneDrive link"],
          "aka.ms": ["Microsoft shortener"],
          "w3.org": ["W3C namespace"]
        }
      }
    }
  }
}
```

**Analysis:**
- **Mixed URL Sources**: Body + document extraction
- **Domain Reputation**: Microsoft domains (likely safe) + OneDrive (requires verification)
- **Threat Assessment**: Low-Medium - legitimate file sharing or potential credential harvesting

---

## Security Analysis Decision Framework

### High Priority Indicators
1. **Deep Nesting** (level ≥ 3)
2. **Domain Mismatches** across layers
3. **URL Shorteners** in deep layers
4. **Generic Senders** with specific requests
5. **Urgency Language** combined with external links
6. **Document URLs** to non-corporate domains

### Medium Priority Indicators
1. **Moderate Nesting** (level 2)
2. **Mixed Domain Reputation**
3. **Social Engineering** language patterns
4. **Attachment-Heavy** communications

### Low Priority Indicators
1. **Shallow Nesting** (level 0-1)
2. **Corporate Domain** consistency
3. **Known Security Tools** (Proofpoint wrappers)
4. **Internal Communications**

### Analysis Workflow
1. **Map the Architecture**: Identify carrier vs. payload layers
2. **Focus Analysis**: Concentrate on levels 2+ for actual threats
3. **Cross-Reference**: Compare URLs, domains, and content across layers
4. **Context Assessment**: Consider sender relationships and business context
5. **Risk Scoring**: Weight indicators by layer depth and consistency

---

## Conclusion

Effective email threat analysis requires understanding the **layered nature** of modern attacks. The JSON structure provides all necessary data points, but analysts must focus their attention on the **payload layers** (typically level 2+) while understanding the **carrier mechanisms** that delivered the threat.

Remember: **The deeper the nesting, the greater the scrutiny required.**