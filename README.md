# Secure Web Application Case Study: Authentication, Access Control & Cloud Deployment

A write-up of a full-stack web application built with security as the primary design
constraint: user registration and login, two-factor authentication and role-gated admin
approval workflows.

This document is a case study built from the project's design documentation and the code
excerpts within it, rather than a runnable repository. Snippets below are excerpts, not
complete files.

## Problem

Build a web platform where users register, authenticate, and submit requests that an admin
reviews and approves or rejects, with every layer of the request/response cycle treated as a
potential attack surface: input handling, session management, file uploads, and access
control all needed explicit, justified security decisions rather than framework defaults.

## Stack

PHP (procedural, `mysqli` with prepared statements), MySQL/MariaDB, PHPMailer for
transactional email, Google reCAPTCHA v3, session-based authentication state.

## Authentication & Registration

Every field is sanitized on the way in, and duplicate accounts are rejected before insertion:

```php
// XSS mitigation on all incoming fields
$name = htmlspecialchars(string: $name, flags: ENT_QUOTES, encoding: 'UTF-8');
$email = htmlspecialchars(string: $email, flags: ENT_QUOTES, encoding: 'UTF-8');
$password = htmlspecialchars(string: $password, flags: ENT_QUOTES, encoding: 'UTF-8');

// Check if email already exists
$checkEmail = $conn->prepare(query: "SELECT id FROM users WHERE email = ?");
$checkEmail->bind_param(types: "s", var: &$email);
$checkEmail->execute();
$checkEmail->store_result();

if ($checkEmail->num_rows > 0) {
    $error = "This email is already registered.";
}
```

Passwords are salted per-user before hashing, and accounts can't log in until email
verification completes:

```php
$salt = bin2hex(string: random_bytes(length: 16));
$hashed_password = hash(algo: 'sha256', data: $password . $salt);

$activation_code = bin2hex(string: random_bytes(length: 16));
// account remains inactive until this code is confirmed via emailed link
```

Password policy is enforced server-side before an account can be created:

```php
if (strlen(string: $password) < 8 ||
    !preg_match(pattern: '/[A-Z]/', subject: $password) ||
    !preg_match(pattern: '/[a-z]/', subject: $password) ||
    !preg_match(pattern: '/[0-9]/', subject: $password) ||
    !preg_match(pattern: '/[!@#$%^&*]/', subject: $password)) {
    $error = "Password policy: At least 8 characters, one uppercase letter, "
           . "one lowercase letter, one number, and one special character.";
}
```

Registration is gated behind Google reCAPTCHA to blunt automated signup abuse:

```php
$recaptcha_response = $_POST['g-recaptcha-response'];
$recaptcha = file_get_contents(filename: $recaptcha_url . '?secret=' . $recaptcha_secret
                                . '&response=' . $recaptcha_response);
$recaptcha = json_decode(json: $recaptcha, associative: true);

if ($recaptcha['success'] == 1 && $recaptcha['score'] >= 0.5 && $recaptcha['action'] == "register") {
    // proceed with registration
}
```

## CSRF Protection

Every state-changing POST request validates a per-session token before processing:

```php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $token = filter_input(type: INPUT_POST, var_name: 'token', filter: FILTER_SANITIZE_FULL_SPECIAL_CHARS);

    if (!$token || $token !== $_SESSION['token']) {
        echo '<p class="error">Error: invalid form submission</p>';
        header(header: $_SERVER['SERVER_PROTOCOL'] . ' 405 Method Not Allowed');
        exit;
    }
}
```

This pattern is applied across registration, login, evaluation request
submission, and admin approve/reject actions.

## Login, Rate Limiting & Two-Factor Authentication

Failed login attempts lock the account for a cooldown period.

```php
$max_attempts = 5;
$lock_time = 10 * 60;

if ($_SESSION['failed_attempts'] >= $max_attempts) {
    $lock_time_left = $_SESSION['lock_time'] - time();
    if ($lock_time_left > 0) {
        $lock_time_left_minutes = ceil(num: $lock_time_left / 60);
        $error = "Too many failed login attempts. Please try again in "
               . "$lock_time_left_minutes minutes.";
        exit;
    }
}
```

On successful password verification, a second factor is required before the session is fully
trusted:

```php
$two_factor_code = rand(min: 100000, max: 999999);

$stmt_update = $conn->prepare(query: "UPDATE users SET two_factor_code = ?, "
                                     . "two_factor_verified = 0 WHERE id = ?");
$stmt_update->bind_param(types: "si", var: &$two_factor_code, vars: &$id);
$stmt_update->execute();

$mail = new PHPMailer(exceptions: true);
// ... emails $two_factor_code to the user
```

Every subsequent protected page checks `two_factor_verified` server-side before rendering.

```php
$stmt = $conn->prepare(query: "SELECT two_factor_verified FROM users WHERE id = ?");
$stmt->bind_param(types: "i", var: &$_SESSION['user']);
$stmt->execute();
$stmt->bind_result(var: &$two_factor_verified);
$stmt->fetch();

if ($two_factor_verified == 0) {
    header(header: "Location: two_factor.php");
    exit();
}
```

## Password Recovery

Recovery requires answering a security question set at registration, then issues a
single-use, randomly generated reset code.

```php
if ($security_answer == $stored_answer) {
    $reset_code = bin2hex(string: random_bytes(length: 16));
}
```

On successful reset, the password is re-salted and re-hashed, the same as at registration,
and the reset code is invalidated:

```php
$salt = bin2hex(string: random_bytes(length: 16));
$hashed_password = hash(algo: 'sha256', data: $new_password . $salt);

$updateStmt = $conn->prepare(query: "UPDATE users SET password = ?, salt = ?, "
                                     . "reset_code = NULL WHERE reset_code = ?");
```

## File Upload Handling

User-submitted photo uploads are validated on both MIME type and size before being written to
disk, and the stored filename is sanitized to prevent directory traversal:

```php
$allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
$file_type = mime_content_type(filename: $photo_tmp_name);

if (in_array(needle: $file_type, haystack: $allowed_types)) {
    $max_file_size = 5 * 1024 * 1024;
    if ($_FILES['photo']['size'] > $max_file_size) {
        $error = "File is too large! The maximum size is 5 MB.";
    }
}

// Directory traversal mitigation
$photo_path = 'uploads/' . basename(path: $photo_name);
```

The submission endpoint itself is only reachable by authenticated, 2FA-verified users, and
all inserted values go through prepared statements:

```php
$stmt = $conn->prepare(query: "SELECT two_factor_verified FROM users WHERE id = ?");
// ... gate access ...

$stmt = $conn->prepare(query: "INSERT INTO evaluation_requests (user_id, request_title, "
                              . "request_description, contact_method, photo_path) "
                              . "VALUES (?, ?, ?, ?, ?)");
$stmt->bind_param(types: "issss", var: &$user_id, vars: &$request_title,
                   $request_description, $contact_method, $photo_path);
```

## Admin Access Control

The admin request-listing and approve/reject actions are gated by role, not just by login
state:

```php
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header(header: 'Location: dashboard.php');
    exit();
}
```

Approve/reject links carry the same CSRF token pattern used elsewhere, so an admin session
can't be tricked into approving a request via a forged link from another page:

```php
<a href="admin_panel.php?id=<?php echo $row['id']; ?>&action=approved&csrf_token=<?php echo $_SESSION['token']; ?>">Approve</a>
```