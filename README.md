# Building — A Version Control System 

**Objective:** Build a local version control system that tracks file changes, stores snapshots efficiently, and supports commit history. Every component maps directly to operating system and filesystem concepts.

**Platform:** Ubuntu 22.04
# Version Control System from Scratch

## Overview

This project is a lightweight **Git-inspired Version Control System (VCS)** implemented in **C**. It demonstrates core **Operating Systems** and **File System** concepts by implementing local version control from scratch, including object storage, staging, directory snapshots, commit history, and repository metadata management.

The system stores file contents using **content-addressable storage**, maintains snapshots through **tree objects**, tracks staged changes using an **index**, and records repository history using **commit objects** linked together by parent references.

---

## Features

* Content-addressable object storage using **SHA-256**
* Efficient object deduplication
* Atomic object writes using temporary files and `rename()`
* Tree objects representing directory structures
* Index (staging area) for tracking file changes
* Commit creation and history traversal
* Repository initialization
* File addition and staging
* Status reporting for staged, modified, deleted, and untracked files
* Commit log generation
* Integrity verification of stored objects

---

## Project Structure

```
.
├── object.c        # Object storage implementation
├── object.h
├── tree.c          # Tree object creation and serialization
├── tree.h
├── index.c         # Staging area implementation
├── index.h
├── commit.c        # Commit creation and history
├── commit.h
├── student.h       # Shared definitions (if provided)
├── Makefile
├── tests/
└── README.md
```

---

## Core Components

### 1. Object Storage

Implements Git-style object storage.

Features include:

* Blob, Tree, and Commit object types
* SHA-256 hashing
* Content-addressable storage
* Object deduplication
* Directory sharding using hash prefixes
* Atomic writes
* Integrity verification during object retrieval

---

### 2. Tree Objects

Represents directory hierarchies as tree structures.

Responsibilities include:

* Building directory snapshots from staged files
* Recursive tree creation
* Deterministic serialization
* Nested directory support

---

### 3. Index (Staging Area)

Tracks files that are prepared for the next commit.

Supports:

* Loading existing index
* Saving updated index
* Adding files
* Detecting modified files
* Removing staged files
* Maintaining sorted entries
* Atomic updates

---

### 4. Commit System

Creates immutable repository snapshots.

Each commit contains:

* Root tree hash
* Parent commit hash
* Author information
* Timestamp
* Commit message

Commits are linked together to maintain repository history.

---

## Repository Workflow

```
Initialize Repository
        │
        ▼
Add Files
        │
        ▼
Create Blob Objects
        │
        ▼
Update Index
        │
        ▼
Build Tree Objects
        │
        ▼
Create Commit Object
        │
        ▼
Update HEAD
```

---

## Filesystem Concepts Implemented

* Content-addressable storage
* Atomic file operations
* File hashing
* Filesystem metadata
* Directory hierarchy representation
* Snapshot-based versioning
* Persistent storage
* File integrity verification
* Linked object graphs
* Reference management

---

## Operating System Concepts

* File I/O
* Temporary files
* Atomic `rename()`
* `fsync()` for durable writes
* Filesystem consistency
* Metadata management
* Recursive directory traversal
* Crash-safe storage techniques

---

## Data Structures Used

* Trees
* Linked structures
* Arrays
* Index tables
* SHA-256 hash identifiers

---

## Build

Compile the project using:

```bash
make
```

Run the test suites:

```bash
make test_objects
./test_objects

make test_tree
./test_tree

make test-integration
```

---

## Example Usage

Initialize a repository:

```bash
./init
```

Stage files:

```bash
./add file1.txt file2.txt
```

Check repository status:

```bash
./status
```

Create a commit:

```bash
./commit -m "Initial commit"
```

View commit history:

```bash
./log
```

---

## Learning Outcomes

This project provides hands-on experience with:

* Designing persistent storage systems
* Implementing a simplified version control system
* Building content-addressable object stores
* Applying operating system and filesystem concepts
* Managing repository metadata
* Designing modular software systems in C
* Working with serialization and binary file formats
* Ensuring data consistency through atomic operations


---

## Technologies Used

* C
* POSIX File System APIs
* SHA-256 Hashing
* GNU Make
