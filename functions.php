<?php
require __DIR__ . '/database.php';
session_start();

// ---------- CONNECTING ----------

function getDb(): mysqli
{
    static $conn = null;

    if ($conn === null) {
        global $dbConfig;

        $conn = new mysqli(
            $dbConfig['host'],
            $dbConfig['user'],
            $dbConfig['pass'],
            $dbConfig['name']
        );

        if ($conn->connect_error) {
            die('Database connection failed: ' . $conn->connect_error);
        }

        $conn->set_charset('utf8mb4');
    }

    return $conn;
}

// ---------- LOGGING ----------

function logAction(?string $actorUserId, string $action): void
{
    $conn = getDb();

    $stmt = $conn->prepare("
        INSERT INTO logs (id, user_id, action)
        VALUES (UUID(), ?, ?)
    ");
    $stmt->bind_param('ss', $actorUserId, $action);
    $stmt->execute();
    $stmt->close();
}

// ---------- USER MANAGEMENT ----------

function createUser(
    string $email,
    string $password,
    string $name = null,
    string $address = null,
    ?int $postNr = null,
    string $phone = null,
    ?string $birthdate = null, // 'YYYY-MM-DD'
    string $role = 'Andel',
    ?string $actorUserId = null
): ?string {
    $conn = getDb();

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $idResult = $conn->query("SELECT UUID() AS id");
    $row = $idResult->fetch_assoc();
    $userId = $row['id'];

    $stmt = $conn->prepare("
        INSERT INTO users (
            id, email, password, role, name, address, post_nr, phone, birthdate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");

    $stmt->bind_param(
        'ssssssiss',
        $userId,
        $email,
        $passwordHash,
        $role,
        $name,
        $address,
        $postNr,
        $phone,
        $birthdate
    );

    $ok = $stmt->execute();
    $stmt->close();

    if (!$ok) {
        return null;
        //log fejl her?
    }

    logAction($actorUserId, "Created user {$userId}");

    return $userId;
}

//SOFT DELETE
function deleteUser(string $targetUserId, string $actorUserId): bool
{
    $conn = getDb();

    $stmt = $conn->prepare("
        UPDATE users
        SET status = 'deleted'
        WHERE id = ? AND status <> 'deleted'
    ");
    $stmt->bind_param('s', $targetUserId);
    $ok = $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();

    if ($ok && $affected > 0) {
        logAction(
            $actorUserId,
            "Deleted user {$targetUserId}"
        );
        return true;
    }

    return false;
}

function updateUserProfile(
    string $targetUserId,
    ?string $name,
    ?string $address,
    ?int $postNr,
    ?string $phone,
    ?string $birthdate,
    string $actorUserId
): bool {
    $conn = getDb();

    $stmt = $conn->prepare("
        UPDATE users
        SET name = ?, address = ?, post_nr = ?, phone = ?, birthdate = ?
        WHERE id = ? AND status = 'active'
    ");

    $stmt->bind_param(
        'ssisss',
        $name,
        $address,
        $postNr,
        $phone,
        $birthdate,
        $targetUserId
    );

    $ok = $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();

    if ($ok && $affected > 0) {
        logAction($actorUserId, "Updated user {$targetUserId}");
        return true;
    }

    return false;
}

function generateEmailConfirmToken(string $userId, string $actorUserId = null): ?string
{
    $conn = getDb();

    // Generér token
    $token = bin2hex(random_bytes(32));

    $stmt = $conn->prepare("
        UPDATE users
        SET email_confirm_token = ?
        WHERE id = ?
    ");
    $stmt->bind_param('ss', $token, $userId);

    $ok = $stmt->execute();
    $stmt->close();

    if (!$ok) {
        return null;
    }

    logAction($actorUserId ?? $userId, "Generated email confirm token for {$userId}");

    return $token;
}

function confirmEmailUsingToken(string $token): bool
{
    $conn = getDb();

    // Find bruger med token
    $stmt = $conn->prepare("
        SELECT id
        FROM users
        WHERE email_confirm_token = ?
          AND status = 'active'
        LIMIT 1
    ");
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc() ?: null;
    $stmt->close();

    if (!$user) {
        return false; // Token ugyldig eller slettet bruger
    }

    $userId = $user['id'];

    // Sæt email_confirmed = true og fjern token
    $stmt = $conn->prepare("
        UPDATE users
        SET email_confirmed = 1,
            email_confirm_token = NULL
        WHERE id = ?
    ");
    $stmt->bind_param('s', $userId);
    $ok = $stmt->execute();
    $stmt->close();

    if ($ok) {
        logAction($userId, "Email confirmed");
    }

    return $ok;
}

// ---------- GET INFORMATION ----------

function getUserByEmail(string $email): ?array
{
    $conn = getDb();

    $stmt = $conn->prepare("
        SELECT id, email, password, role, name, status
        FROM users
        WHERE email = ?
        LIMIT 1
    ");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc() ?: null;
    $stmt->close();

    return $user;
}

function getActiveOwnerByShare(string $shareId): ?array
{
    $conn = getDb();

    $stmt = $conn->prepare("
        SELECT u.*
        FROM ownerships o
        JOIN users u ON o.user_id = u.id
        WHERE o.share_id = ?
          AND o.end_date IS NULL
          AND u.status = 'active'
        LIMIT 1
    ");
    $stmt->bind_param('s', $shareId);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc() ?: null;
    $stmt->close();

    return $user;
}

function getActiveSharesByUser(string $userId): array
{
    $conn = getDb();

    $stmt = $conn->prepare("
        SELECT s.*
        FROM ownerships o
        JOIN shares s ON o.share_id = s.id
        WHERE o.user_id = ?
          AND o.end_date IS NULL
          AND s.status = 'active'
    ");
    $stmt->bind_param('s', $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    $shares = [];
    while ($row = $result->fetch_assoc()) {
        $shares[] = $row;
    }

    $stmt->close();

    return $shares;
}

function getShareHistory(string $shareId): array
{
    $conn = getDb();

    $stmt = $conn->prepare("
        SELECT 
            o.*,
            u.email AS owner_email,
            u.name  AS owner_name
        FROM ownerships o
        LEFT JOIN users u ON o.user_id = u.id
        WHERE o.share_id = ?
        ORDER BY o.start_date ASC, o.created_at ASC
    ");
    $stmt->bind_param('s', $shareId);
    $stmt->execute();
    $result = $stmt->get_result();

    $history = [];
    while ($row = $result->fetch_assoc()) {
        $history[] = $row;
    }

    $stmt->close();

    return $history;
}


// ---------- LOGIN / AUTH ----------

function login(string $email, string $password): bool
{
    $user = getUserByEmail($email);

    if (!$user) {
        return false;
    }

    if (!password_verify($password, $user['password'])) {
        return false;
    }

    if ($user['status'] != "active") {
        return false;
    }

    // Login OK → gem i session
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['user_role'] = $user['role'];

    logAction($user['id'], "User logged in");

    return true;
}

function logout(): void
{
    if (isset($_SESSION['user_id'])) {
        logAction($_SESSION['user_id'], "User logged out");
    }

    $_SESSION = [];
    session_destroy();
}

function requireLogin(): void
{
    if (empty($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
}

function createPasswordResetToken(string $email): ?string
{
    $conn = getDb();

    // Find bruger
    $stmt = $conn->prepare("
        SELECT id
        FROM users
        WHERE email = ? AND status = 'active'
        LIMIT 1
    ");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc() ?: null;
    $stmt->close();

    if (!$user) {
        return null;
    }

    $userId = $user['id'];

    // Generér token + udløbstid (1 time)
    $token = bin2hex(random_bytes(32)); // kan bruges direkte i URL
    $expiresAt = (new DateTime('+1 hour'))->format('Y-m-d H:i:s');

    $stmt = $conn->prepare("
        UPDATE users
        SET pw_reset_token = ?, pw_reset_exp_at = ?
        WHERE id = ?
    ");
    $stmt->bind_param('sss', $token, $expiresAt, $userId);
    $ok = $stmt->execute();
    $stmt->close();

    if (!$ok) {
        return null;
    }

    logAction(null, "Created password reset token for user {$userId}");

    return $token; // den sender du med en mail: ?token=...
}

function resetPasswordWithToken(string $token, string $newPassword): bool
{
    $conn = getDb();

    $stmt = $conn->prepare("
        SELECT id
        FROM users
        WHERE password_reset_token = ?
          AND password_reset_expires_at > NOW()
          AND status = 'active'
        LIMIT 1
    ");
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc() ?: null;
    $stmt->close();

    if (!$user) {
        return false; // token ugyldig eller udløbet
    }

    $userId = $user['id'];
    $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);

    // Opdater password + nulstil token
    $stmt = $conn->prepare("
        UPDATE users
        SET password = ?, password_reset_token = NULL, password_reset_expires_at = NULL
        WHERE id = ?
    ");
    $stmt->bind_param('ss', $passwordHash, $userId);
    $ok = $stmt->execute();
    $stmt->close();

    if ($ok) {
        logAction($userId, "Password reset via token");
    }

    return $ok;
}

// ---------- SHARE MANAGEMENT ----------

function createShare(string $nummer, string $actorUserId): ?string
{
    $conn = getDb();

    $res = $conn->query("SELECT UUID() AS id");
    $row = $res->fetch_assoc();
    $shareId = $row['id'];

    $stmt = $conn->prepare("
        INSERT INTO shares (id, nummer, status)
        VALUES (?, ?, 'active')
    ");
    $stmt->bind_param('ss', $shareId, $nummer);
    $ok = $stmt->execute();
    $stmt->close();

    if (!$ok) {
        return null;
    }

    logAction($actorUserId, "Created share {$shareId} (nummer={$nummer})");

    return $shareId;
}

function deleteShare(string $shareId, string $actorUserId): bool
{
    $conn = getDb();

    $stmt = $conn->prepare("
        UPDATE shares
        SET status = 'deleted'
        WHERE id = ? AND status <> 'deleted'
    ");
    $stmt->bind_param('s', $shareId);
    $ok = $stmt->execute();
    $affected = $stmt->affected_rows;
    $stmt->close();

    if ($ok && $affected > 0) {
        logAction($actorUserId, "Deleted share {$shareId}");
        return true;
    }

    return false;
}

function transferShare(
    string $shareId,
    ?string $toUserId,
    string $actorUserId,
    ?string $reason = null
): bool {
    $conn = getDb();
    $conn->begin_transaction();

    try {
        $today = date('Y-m-d');

        // Find evt. nuværende ejer
        $stmt = $conn->prepare("
            SELECT id, user_id, lookup
            FROM ownerships
            WHERE share_id = ? AND end_date IS NULL
            LIMIT 1
        ");
        $stmt->bind_param('s', $shareId);
        $stmt->execute();
        $result = $stmt->get_result();
        $current = $result->fetch_assoc() ?: null;
        $stmt->close();

        $fromUserId = $current['user_id'] ?? null;

        // Afslut nuværende ejerskab
        if ($current) {
            $stmt = $conn->prepare("
                UPDATE ownerships
                SET end_date = ?
                WHERE id = ?
            ");
            $stmt->bind_param('ss', $today, $current['id']);
            $stmt->execute();
            $stmt->close();
        }

        // Opret nyt ejerskab, hvis der er en ny ejer
        if ($toUserId !== null) {
            $res = $conn->query("SELECT UUID() AS id");
            $row = $res->fetch_assoc();
            $ownershipId = $row['id'];

            // Ny lookup – kan gøres pænere senere (fx kortere kode)
            $lookup = bin2hex(random_bytes(16));

            $stmt = $conn->prepare("
                INSERT INTO ownerships (id, user_id, share_id, lookup, start_date, end_date)
                VALUES (?, ?, ?, ?, ?, NULL)
            ");
            $stmt->bind_param('sssss', $ownershipId, $toUserId, $shareId, $lookup, $today);
            $stmt->execute();
            $stmt->close();
        }

        $conn->commit();

        // Log tekst
        if ($toUserId === null) {
            logAction(
                $actorUserId,
                "Transferred share {$shareId} from {$fromUserId} to nobody (removed owner). Reason: {$reason}"
            );
        } else {
            logAction(
                $actorUserId,
                "Transferred share {$shareId} from {$fromUserId} to {$toUserId}. Reason: {$reason}"
            );
        }

        return true;
    } catch (Throwable $e) {
        $conn->rollback();
        // evt. ekstra error-log
        return false;
    }
}
