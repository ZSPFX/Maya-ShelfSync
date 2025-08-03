# 🔃 Maya ShelfSync

> Support Autodesk Maya 2022, 2023, 2024, 2025, 2026

🎁 ShelfSync let you sync your shelves across different Maya versions or machines through cloud storage like Dropbox, Google Drive, OneDrive, etc.

![Tab UI](https://github.com/zspfx/Maya-ShelfSync/blob/main/images/TabUI.png?raw=true)

![Maya](https://img.shields.io/static/v1?message=Maya&color=0696D7&logo=Autodesk&logoColor=white&label=) ![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

## Use case

-   Share/Sync shelves across different Maya versions
-   Share shelves among team members through cloud storage

## Features

-   Sharing and syncing shelves with custom icons
-   Joining/leaving multiple team (Each team has their own shelves, like a group)
-   Automatically sync all shelves when you open Maya
-   Admin password protected for publishing shelves (Prevent unauthorized publishing among team members)
-   Preview shelves before publishing

## Installation

1.  Download the latest .py version of the plugin from the [Releases](https://github.com/zspfx/Maya-ShelfSync/releases) page.

2.  Copy the downloaded .py file to the `C:\Users\<Username>\Documents\maya\<Version>\plug-ins` folder.

3.  Open Maya and go to `Windows > Settings/Preferences > Plug-in Manager` and enable the plugin then a new **ShelfSync** tab will appear.

## ⭐ Get Started

### Create a Team / Sharing shelves

1. `ShelfSync -> Add Team` choose any folder you wanted it to acts as a repository to store shelves in.

2. Set a **Team Name** and **Admin Password** which is used for publishing shelves. Then select list of shelves you wanted to share.

3. After publishing, you'll be ask to enter the **Admin Password** to publish the shelves.

You're set! :)

### Joining a Team / Loading shelves

> You can use other maya version to join the team or actual team members from their machine if you sync the repository correctly.

1. `ShelfSync -> Add Team` choose the repository folder you wish to join.

You're set! :D

> Shelves will be updated automatically when you open Maya or sync manually.

## FAQ

### How does password protection work?

To sync the shelves, its hash has to be signed with the unlocked RSA private key which only the publisher knows the password of to unlock the key and use it for signing. The public key is used to verify the signature which every team member will store a copy of them locally on their machine to verify its integrity and authenticity before syncing.
