<?php
declare(strict_types=1);

// INTENTIONALLY VULNERABLE. Run only inside the local Docker Compose lab.
$term = (string) ($_POST['term'] ?? '');
$message = (string) ($_GET['message'] ?? '');
$file = (string) ($_GET['file'] ?? '');

$rows = [];
$sqlError = '';
if ($term !== '') {
    $db = new PDO('sqlite::memory:');
    $db->exec("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT)");
    $db->exec("INSERT INTO products (name, description) VALUES
        ('Notebook', 'Paper notebook'),
        ('Pen', 'Blue ballpoint pen'),
        ('Backpack', 'Canvas backpack')");

    // SQLi: user input is concatenated directly into the SQL statement.
    $sql = "SELECT name, description FROM products WHERE name LIKE '%" . $term . "%'";
    try {
        $rows = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $error) {
        $sqlError = 'Invalid search expression.';
    }
}

$fileContents = '';
$fileError = '';
if ($file !== '') {
    // LFI: the path is not constrained to the demo directory.
    $contents = @file_get_contents($file);
    if ($contents === false) {
        $fileError = 'Could not read the requested file.';
    } else {
        $fileContents = $contents;
    }
}

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>minimal-waf · local security lab</title>
    <style>
        :root { color-scheme: dark; font-family: system-ui, sans-serif; }
        body { max-width: 860px; margin: 3rem auto; padding: 0 1rem; background: #0b1220; color: #e2e8f0; }
        h1 { margin-bottom: .25rem; }
        p { line-height: 1.5; }
        .warning { border: 1px solid #f59e0b; background: #451a03; padding: 1rem; border-radius: .75rem; }
        .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
        section { border: 1px solid #334155; border-radius: .75rem; padding: 1.25rem; background: #111c2e; }
        label { display: block; margin-bottom: .4rem; }
        input { box-sizing: border-box; width: 100%; padding: .7rem; border: 1px solid #64748b; border-radius: .4rem; }
        button { margin-top: .7rem; padding: .65rem 1rem; border: 0; border-radius: .4rem; cursor: pointer; }
        pre { white-space: pre-wrap; overflow-wrap: anywhere; }
        code { color: #67e8f9; }
        .result { margin-top: 1rem; padding: .7rem; background: #0b1220; border-radius: .4rem; }
    </style>
</head>
<body>
    <h1>minimal-waf · security lab</h1>
    <p class="warning"><strong>Intentionally vulnerable.</strong> This page exists only to test a locally isolated WAF. Never expose the PHP service or this lab to the internet.</p>
    <p>Three independent inputs, three common classes of bug. In <code>block</code> mode, known attack patterns should receive HTTP 403 before PHP sees them.</p>

    <div class="grid">
        <section>
            <h2>SQL injection</h2>
            <form method="post" action="/">
                <label for="term">Product search</label>
                <input id="term" name="term" value="<?= escape($term) ?>" placeholder="Pen">
                <button type="submit">Search</button>
            </form>
            <?php if ($term !== ''): ?>
                <div class="result">
                    <?php if ($sqlError !== ''): ?>
                        <p><?= escape($sqlError) ?></p>
                    <?php elseif ($rows === []): ?>
                        <p>No products found.</p>
                    <?php else: ?>
                        <ul>
                        <?php foreach ($rows as $row): ?>
                            <li><?= escape($row['name']) ?> — <?= escape($row['description']) ?></li>
                        <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </section>

        <section>
            <h2>Reflected XSS</h2>
            <form method="get" action="/">
                <label for="message">Message</label>
                <input id="message" name="message" value="<?= escape($message) ?>" placeholder="Hello, world!">
                <button type="submit">Display</button>
            </form>
            <?php if ($message !== ''): ?>
                <div class="result">
                    <!-- XSS: the response deliberately renders unescaped user input. -->
                    <p><?= $message ?></p>
                </div>
            <?php endif; ?>
        </section>

        <section>
            <h2>Local file inclusion</h2>
            <form method="get" action="/">
                <label for="file">File path</label>
                <input id="file" name="file" value="<?= escape($file) ?>" placeholder="welcome.txt">
                <button type="submit">Read file</button>
            </form>
            <?php if ($file !== ''): ?>
                <div class="result">
                    <?php if ($fileError !== ''): ?>
                        <p><?= escape($fileError) ?></p>
                    <?php else: ?>
                        <pre><?= escape($fileContents) ?></pre>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </section>
    </div>
</body>
</html>
