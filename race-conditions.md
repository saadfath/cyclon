# Race Conditions

## 1. Description

A Race Condition is a vulnerability that occurs when the behavior of an application depends on the timing or ordering of multiple operations accessing shared resources.

When multiple threads, processes, or requests access and modify shared data concurrently without proper synchronization, unexpected results may occur.

One important type of race condition is Time-of-Check to Time-of-Use (TOCTOU).

TOCTOU occurs when an application checks a condition and then uses a resource, but the resource changes between those two operations.

Potential consequences include:

- Unauthorized access.
- Incorrect financial transactions.
- Data corruption.
- Duplicate operations.
- Bypassing business rules.
- Inconsistent application state.
- Unauthorized file operations.

### Example

Imagine an application that allows users to withdraw money from an account.

The application checks whether the account has sufficient funds and then performs the withdrawal.

If two requests execute simultaneously, both may pass the balance check before either updates the account.

This may result in an incorrect final balance.

## 2. Common Causes

Race conditions commonly occur when:

- Multiple requests modify shared data simultaneously.
- Database operations are not properly synchronized.
- Applications perform separate checks and updates.
- Shared variables are accessed without synchronization.
- File operations depend on previously checked conditions.
- Transactions are not atomic.
- Concurrent operations can violate business rules.
- Applications use unsafe locking mechanisms.
- Distributed services do not coordinate shared state correctly.

## 3. Vulnerable Code Patterns

### Pattern 1: Shared counter without synchronization

Python example:

```python
balance = 100

def withdraw(amount):
    global balance

    if balance >= amount:
        balance -= amount

    return balance
```

**Problem:**

The balance check and update are separate operations.

Concurrent execution may cause inconsistent results.

The Python Global Interpreter Lock (GIL) does not make arbitrary multi-step business operations atomic.

### Pattern 2: Separate database check and update

```python
def withdraw(account, amount):
    balance = get_balance(account)

    if balance >= amount:
        update_balance(account, balance - amount)

        return True

    return False
```

**Problem:**

Another transaction may modify the balance after `get_balance()` but before `update_balance()`.

The application does not ensure that checking and updating happen as one protected operation.

### Pattern 3: Unsafe file check and use

```python
import os

def process_file(path):
    if os.path.exists(path):
        with open(path, "r") as file:
            return file.read()
```

**Problem:**

The file may change between the existence check and the file-opening operation.

This is a potential TOCTOU issue when the filesystem or another process can modify the target.

## 4. Safer Implementation

A secure implementation should:

- Use database transactions for related operations.
- Apply appropriate transaction isolation.
- Use atomic database updates.
- Use locks when protecting shared in-memory state.
- Avoid separating security checks from resource operations.
- Use safe filesystem APIs.
- Apply unique constraints where duplicate operations must be prevented.
- Design distributed operations to handle concurrency correctly.
- Use idempotency controls for operations that must not execute more than once.

### Example: Thread-safe shared state

```python
import threading

balance = 100
lock = threading.Lock()

def withdraw(amount):
    global balance

    with lock:
        if balance >= amount:
            balance -= amount
            return True

        return False
```

**Explanation:**

- `threading.Lock()` creates a synchronization lock.
- `with lock` ensures that only one thread executes the protected section at a time.
- The balance check and update happen while the lock is held.

**Important:** This protects threads sharing the same Python process. It does not protect against concurrent requests handled by multiple processes or servers. Database transactions or distributed coordination may be necessary.

## 5. Detection Indicators

Cyclone should investigate the following patterns:

| Indicator | Description |
|---|---|
| Shared mutable state | Multiple execution paths modify the same data. |
| Check-then-act operations | A condition is checked before a separate resource operation. |
| Non-atomic updates | Related operations are performed independently. |
| Missing synchronization | Shared resources are accessed without appropriate locking. |
| Database read-modify-write | Data is read, modified, and written without concurrency protection. |
| Duplicate operations | Concurrent requests can perform the same action multiple times. |
| Unsafe filesystem operations | File checks and subsequent operations are separated. |
| Missing transaction controls | Related database changes are not protected by transactions. |

These indicators are not proof of a vulnerability. Cyclone must establish whether concurrent execution can produce an unsafe outcome.

## 6. Python Functions and Libraries to Inspect

Cyclone should inspect concurrency and synchronization functionality.

### Threading

```python
threading.Thread()
threading.Lock()
threading.RLock()
threading.Semaphore()
```

### Multiprocessing

```python
multiprocessing.Process()
multiprocessing.Lock()
multiprocessing.Value()
```

### Asyncio

```python
asyncio.create_task()
asyncio.Lock()
asyncio.gather()
```

### Database operations

```python
connection.commit()
connection.rollback()
cursor.execute()
```

### Filesystem operations

```python
os.path.exists()
open()
os.replace()
os.rename()
```

The presence or absence of these functions does not automatically establish a race condition.

Cyclone must inspect how resources are shared and whether operations are correctly synchronized.

## 7. Detection Logic for Cyclone

Cyclone should analyze concurrency behavior using the following process:

1. Identify shared resources and mutable state.
2. Identify functions that read and modify those resources.
3. Determine whether multiple threads, processes, or requests can execute these functions concurrently.
4. Identify check-then-act sequences.
5. Inspect database transactions and isolation levels.
6. Search for synchronization mechanisms.
7. Determine whether the synchronization covers the complete critical operation.
8. Identify operations that may be repeated or executed concurrently.
9. Inspect filesystem checks followed by resource operations.
10. Determine whether concurrent execution can violate a security property or business rule.

### Important distinction

Using multiple threads or asynchronous functions does not automatically indicate a race condition.

Likewise, the absence of a Python lock does not automatically indicate a vulnerability.

For example, a database may already provide the required atomicity through transactions or conditional updates.

Cyclone must analyze the complete execution context.

## 8. Severity Assessment

| Severity | Conditions |
|---|---|
| Critical | Concurrent execution can cause severe compromise of critical resources or security controls. |
| High | Race conditions allow significant unauthorized operations or financial/business-rule violations. |
| Medium | Concurrent execution can cause meaningful data corruption or inconsistent application behavior. |
| Low | Limited concurrency issues with restricted impact. |
| Informational | Potential race patterns without sufficient evidence of unsafe outcomes. |

Severity should consider:

- Whether concurrent execution is possible.
- Which resources are affected.
- Whether security checks can be bypassed.
- Whether financial or sensitive operations are involved.
- Whether the issue can cause data corruption.
- Existing transaction and synchronization protections.

Do not assign severity based only on shared variables or missing locks.

## 9. Evidence Collection

For every potential race-condition finding, Cyclone should collect:

- File name.
- Function name.
- Line number.
- Shared resource.
- Read operations.
- Write operations.
- Execution context.
- Concurrent access paths.
- Synchronization mechanisms.
- Database transaction configuration.
- Check-then-use sequences.
- Potential impact.

Cyclone must distinguish between confirmed evidence and assumptions.

## 10. Recommended Fixes

- Use atomic database operations.
- Protect shared mutable state with appropriate locks.
- Use database transactions for related operations.
- Apply suitable transaction isolation levels.
- Use unique constraints to prevent duplicate records.
- Use conditional updates instead of separate read-modify-write operations.
- Avoid unsafe check-then-use filesystem patterns.
- Use atomic filesystem operations where appropriate.
- Apply idempotency controls to sensitive operations.
- Use distributed locking only when necessary and with appropriate failure handling.
- Test concurrent execution of security-sensitive operations.

## 11. False Positives

Cyclone should avoid reporting every shared variable or concurrent function as vulnerable.

Possible false positives include:

- Data that is immutable.
- Operations already protected by database transactions.
- Atomic database updates.
- Shared state protected by appropriate locks.
- Operations that cannot execute concurrently.
- Filesystem operations using safe atomic primitives.
- Framework-managed synchronization.

The scanner should inspect the complete execution context before reporting a vulnerability.

## 12. RAG Knowledge Summary

**Vulnerability:** Race Conditions

**Category:** Concurrency / State Management

**Affected Languages:** Python and other languages supporting concurrent execution.

**Primary Risk:** Concurrent operations may produce unexpected state changes, bypass business rules, or compromise security controls.

**Common Sources:**
- Concurrent HTTP requests.
- Background workers.
- Multiple threads.
- Multiple processes.
- Asynchronous tasks.
- Distributed services.

**Common Sinks:**
- Shared variables.
- Database updates.
- File operations.
- Account balances.
- Inventory records.
- Authentication and authorization state.

**Detection Strategy:**

Identify shared mutable resources, trace concurrent read and write operations, inspect check-then-act sequences, and evaluate whether synchronization or atomic operations protect critical functionality.

**Recommended Fix:**

Use atomic operations, database transactions, appropriate synchronization mechanisms, and safe resource-handling patterns.

**Confidence Requirements:**

Shared state or concurrent execution alone is insufficient to confirm a vulnerability. Cyclone must establish a possible unsafe interleaving of operations and identify its impact.

**Important:**

Race Conditions and TOCTOU are related but not identical.

- Race Conditions describe unexpected behavior caused by the timing of concurrent operations.
- TOCTOU is a specific pattern where a resource changes between a security check and its subsequent use.

RAG should provide security knowledge and explain findings. The scanner's actual code analysis must independently establish whether the vulnerability exists.
