# Disk & Cache Management

Mini-Ops helps keep your VPS clean by managing space occupied by caches and logs.

## 🧹 Cache Cleaning

In the "Disk Management" section, you can clean:

1.  **Rust Build (`target/`)**:
    - **Description**: Compilation artifacts (if you build on the server).
    - **Size**: Can reach several GBs.
    - **Impact**: Safe to delete. Next build will take longer.

2.  **Frontend Cache (`node_modules/`)**:
    - **Description**: Dependencies and build cache.
    - **Impact**: Safe to delete if you are not actively developing on the server. `npm install` will restore them.

3.  **Docker System**:
    - **Action**: Equivalent to `docker system prune -a`.
    - **Impact**: Removes stopped containers, unused networks, and dangling images.
    - **Warning**: Make sure you don't need stopped containers!

4.  **System Logs**:
    - **Action**: Vacuum journald logs (keep last 2 days / 500MB).
    - **Requirement**: Requires `root` or `sudo` privileges.

## ⚠️ Notes for Non-Root Users

If running as `miniops` user:
- **System Logs**: Cleaning likely won't work (Permission Denied).
- **Build/Frontend**: Works if the user owns the directories.
