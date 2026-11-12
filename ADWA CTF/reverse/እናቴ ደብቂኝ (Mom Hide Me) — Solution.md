---
title: "እናቴ ደብቂኝ (Mom Hide Me) — Solution"
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "reverse"
  - "adwa-ctf"
category: "reverse"
platform: "ADWA CTF"
---

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

========================================================
  ADWA CTF - እናቴ ደብቂኝ (Mom Hide Me) / CrackMe
  Category: Web | Difficulty: Easy | Points: 100
  Author: onegash3
========================================================

![እናቴ ደብቂኝ](../../pics/%E1%8A%A5%E1%8A%93%E1%89%B0%20%E1%8B%B0%E1%89%A5%E1%89%82%E1%8A%9D.png)

HINT (from challenge page):
  "Try to find in mass"

========================================================
  STEP-BY-STEP SOLUTION
========================================================

WHAT YOU NEED:
  - The binary file: s1nqerwus7cpmnyneuz9 (or "CrackMe")
  - A terminal
  - An ADWA CTF account

========================================================
STEP 1: IDENTIFY THE FILE
========================================================
Run this command to see what type of file it is:

  file s1nqerwus7cpmnyneuz9

Expected output:
  ELF 64-bit LSB executable ... dynamically linked ...
  This confirms it's a Linux executable program.

========================================================
STEP 2: RUN THE PROGRAM
========================================================
Make it executable and run it:

  chmod +x s1nqerwus7cpmnyneuz9
  ./s1nqerwus7cpmnyneuz9

You'll see:
  Enter password:

Type anything (e.g., "test") and press Enter.
It will say:
  Wrong Password.

========================================================
STEP 3: FIND THE PASSWORD
========================================================
Use the strings command to extract all hidden text:

  strings s1nqerwus7cpmnyneuz9

Look through the output. You'll see many decoy/fake strings like:
  [REDACTED]
  [REDACTED]
  [REDACTED]
  [REDACTED]

Among them, the actual password stands out:
  wrongpass

Run the program again and enter wrongpass:

  ./s1nqerwus7cpmnyneuz9
  Enter password: wrongpass

Output:
  Access Granted!

But wait — no flag is printed! The binary just says "Access Granted!" and exits.

========================================================
STEP 4: FIND THE FLAG FORMAT
========================================================
The challenge hint says "Try to find in mass" — meaning look through the
MASS of strings/data in the binary.

Notice the decoy strings use a specific flag format:
  cXc{...}   (not ADWA{...})

The actual flag also uses this format: cXc{...}

Look through the strings more carefully. The decoy strings are meant to
mislead, but the format cXc{...} is the real pattern.

========================================================
STEP 5: SUBMIT THE FLAG
========================================================
Go to https://adwactf.com
Log in to your account
Go to Dashboard -> Challenges
Find challenge "እናቴ ደብቂኝ 🫣"
Click "Submit Flag"
Enter: [REDACTED]
You get 100 points!

========================================================
  WHAT WE LEARNED
========================================================
  - Flag format isn't always the CTF name (ADWA{...})
  - The binary author's flag format cXc{...} was visible in decoy strings
  - "Try to find in mass" = search through the masses of strings
  - The password "wrongpass" gives "Access Granted!" but the real
    flag is submitted separately on the web platform

========================================================
  Flag: [REDACTED]
========================================================
