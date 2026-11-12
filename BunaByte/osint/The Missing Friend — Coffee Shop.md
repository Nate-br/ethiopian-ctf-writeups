---
title: "The Missing Friend — Coffee Shop"
category: osint
platform: BunaByte
difficulty: Easy
points: 75
solves: 59
flag: "[REDACTED]"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "osint"
  - "bunabyte"
---

# The Missing Friend — Coffee Shop

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

![The Missing Friend](../../pics/the%20missing%20friend.png)

## Challenge

A photo-based OSINT challenge: a missing friend left behind a picture of the coffee shop where they were last seen, plus a cryptic clue about their whereabouts. The task is to identify the establishment.

**Files:** `coffee.zip` → `image.jpg`

**Knowns:**

- Location: Addis Ababa, Ethiopia
- Clue: *"I'm chilling where the coffee is strong and the view is green."*
- Flag format: `BB{location-name}` (example: `[REDACTED]`)

## Solution

### 1. Extract and Analyze the Challenge

```bash
unzip coffee.zip
Files: image.jpg

file image.jpg
image.jpg: JPEG image, 900x500 pixels
```

The challenge provides:

- A photo of a coffee shop exterior
- Location: Addis Ababa, Ethiopia
- Clue: "I'm chilling where the coffee is strong and the view is green."
- Flag format: `BB{location-name}` (example: `[REDACTED]`)

### 2. Analyze the Photo

The photo shows:

- A modern, upscale coffee shop with large glass windows
- Marble/stone facade on the building
- Green plants in decorative stone/concrete pots outside
- An orange/red poster/sign visible through the window
- A dark-colored car parked nearby
- Urban street setting

Key observations:

- The shop has a modern, polished appearance
- The marble/stone facade suggests an established, premium location
- The orange/red signage could be a brand identifier
- The green plants are prominent and decorative

### 3. Analyze the Clue

> "I'm chilling where the coffee is strong and the view is green."

Breaking this down:

- **"coffee is strong"** — Ethiopian coffee is world-renowned for its strong, distinctive flavor
- **"the view is green"** — the shop has green plants/greenery visible (confirmed by the photo showing multiple green plants)

This clue points to a specific coffee shop in Addis Ababa.

### 4. Research Coffee Shops in Addis Ababa

Addis Ababa is the birthplace of coffee and has a rich coffee culture. Major coffee shops include:

1. **Tomoca Coffee (TO.MO.CA)**
   - Founded: 1953
   - Meaning: *Torrefazione Moderna Cafe* (Modern Coffee Roasting)
   - Ethiopia's first commercial coffee roaster
   - Famous for Italian-style coffee with Ethiopian beans
   - Multiple branches across Addis Ababa
   - One of the most recognized coffee brands in Ethiopia

2. **Green Gold Coffee**
   - Modern specialty coffee chain
   - Multiple locations: Skylight, Bambis, Entoto Park, Andinet Park
   - Focus on specialty coffee and roasting

3. **Tomatina Coffee**
   - Another popular chain in Addis Ababa

4. Various independent cafes

### 5. Match Photo to Tomoca Coffee

The photo matches Tomoca Coffee's modern branches:

- Tomoca has multiple locations including:
  - Wawel Street (original/historic location)
  - Bole Road (modern branch)
  - Sarbet District
  - Atlas location
  - Medhane Alem Building
- The modern branches feature:
  - Large glass windows
  - Premium/modern interior design
  - Professional signage and branding
  - Urban street-front locations
- The orange/red poster visible in the window matches Tomoca's branding style
- The marble/stone facade is consistent with Tomoca's established, premium locations

### 6. Verify the Answer

The clue "the coffee is strong" perfectly describes Tomoca:

- Tomoca is **the** iconic Ethiopian coffee brand
- Founded in 1953, it's Ethiopia's oldest commercial roaster
- Known for strong, authentic Ethiopian coffee
- A landmark brand in Ethiopia

The clue "the view is green" matches:

- The green plants visible outside the shop in the photo
- Tomoca's modern branches have decorative greenery

The flag format `[REDACTED]` follows the pattern:

- Name: tomoca
- Category: coffee
- Combined: [REDACTED]

## Flag

```
[REDACTED]
```

## Key Takeaways

- **Photo analysis** — identify key visual elements (building style, signage, plants, location markers) before searching; every detail narrows the candidate set.
- **Geographic profiling** — the stated location (Addis Ababa) bounds the search space; combine it with the clue to rank candidates.
- **Clue interpretation** — break "the coffee is strong and the view is green" into actionable search terms rather than searching the sentence verbatim.
- **Brand recognition** — knowing that Tomoca is Ethiopia's most iconic coffee brand makes "strong coffee" click; domain knowledge about the region is a force multiplier in OSINT.
- **Visual matching** — confirm the answer by matching the photo against the candidate's known aesthetics (glass, marble, greenery) instead of stopping at the first plausible name.
