const express = require("express");
const router = express.Router();
const db = require("../config/db");

// show login page
router.get("/login", (req, res) => {
    res.render("login", { 
        error: null,
        user: req.session.user || null
    });
});
   // Show register page
router.get("/register", (req, res) => {
    res.render("register");
});
router.get('/report', (req, res) => {

    const type = req.query.type;

    res.render('report', {
        type,
        solved: req.session.solved || [],
        attempts: req.session.bruteforceAttempts || []
    });

});
router.get('/feedback', (req, res) => {
  res.render('feedback', { user: req.session.user || {} });
});
router.get("/products", (req, res) => {
    db.query("SELECT * FROM products", (err, results) => {

        if (err) {
            console.log(err);
            return res.send("Database error");
        }

        console.log("PRODUCTS:", results);

        res.render("products", { products: results });
    });
});
router.get('/account', (req, res) => {

    if (!req.session.user) {
        return res.redirect('/login');
    }

    const requestedId = req.query.id;
    const loggedInId = req.session.user.id;

    // 🚨 IDOR DETECTION (CLEAN + RELIABLE)
    if (requestedId && Number(requestedId) !== Number(loggedInId)) {

        if (!req.session.solved) {
            req.session.solved = [];
        }

        if (!req.session.solved.includes("idor")) {
            req.session.solved.push("idor");
        }

        console.log("IDOR DETECTED:", req.session.solved);

        return res.redirect("/report?type=idor");
    }

    // ✅ SAFE ACCESS
    const userId = requestedId || loggedInId;

    const sql = "SELECT * FROM users WHERE id = ?";

    db.query(sql, [userId], (err, result) => {

        if (err) throw err;

        if (!result.length) {
            return res.send("User not found");
        }

        res.render('account', { user: result[0] });
    });
});
router.post("/register", (req, res) => {

    const { username, password, confirmPassword, email } = req.body;

    if (password !== confirmPassword) {
        return res.render("register", { error: "Passwords do not match" });
    }

     if (password.length < 6) {

    // ✅ FIRST update session
    if (!req.session.solved) {
        req.session.solved = [];
    }

    if (!req.session.solved.includes('weak')) {
        req.session.solved.push('weak');
    }

    console.log("WEAK UPDATED:", req.session.solved);

    // ✅ THEN redirect
    return res.redirect("/report?type=weak");
}

    // ✅ XSS FIRST
if (
    username.includes("<script") ||
    username.includes("</script>")
) {
    if (!req.session.solved) {
        req.session.solved = [];
    }

    if (!req.session.solved.includes('xss')) {
        req.session.solved.push('xss');
    }

    return res.redirect("/report?type=xss");
}

// ✅ SQLi SECOND
if (
    username.includes("'") ||
    username.includes("--") ||
    username.toLowerCase().includes(" or ") ||
    username.toLowerCase().includes(" and ")
) {
    if (!req.session.solved) {
        req.session.solved = [];
    }

    if (!req.session.solved.includes('sqli')) {
        req.session.solved.push('sqli');
    }

    return res.redirect("/report?type=sqli&solved=sqli");
}

    const checkUserSql = "SELECT * FROM users WHERE username = ?";

    db.query(checkUserSql, [username], (err, result) => {

        if (err) throw err;

        if (result.length > 0) {
            return res.render("register", { error: "Username already exists" });
            
        }

        const sql = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";

        db.query(sql, [username, password, email], (err, result) => {

            if (err) throw err;

            return res.redirect("/login");

        });

    });

});
let loginAttempts = {};
// handle login
router.post("/login", (req, res) => {

    const { username, password } = req.body;
if (!req.session.bruteforceAttempts) {
    req.session.bruteforceAttempts = [];
}

req.session.bruteforceAttempts.push(password);
   

    // 2️⃣ SQL Injection Detection
    if (
        username.includes("'") ||
        username.toLowerCase().includes("or") ||
        username.includes("--")
    ) {
        console.log("SQL Injection detected!");

        // ✅ SAVE IN SESSION
        if (!req.session.solved) {
            req.session.solved = [];
        }

        if (!req.session.solved.includes("sqli")) {
            req.session.solved.push("sqli");
        }

        console.log("UPDATED SESSION:", req.session.solved);

        return res.redirect("/report?type=sqli");
    }

    // 3️⃣ Normal Login (vulnerable query)
    const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

    db.query(sql, (err, result) => {

        if (err) {
            console.log("ERROR:", err);
            return res.send("Database error");
        }

        if (result && result.length > 0) {
            console.log("LOGIN SUCCESS");

            req.session.user = result[0];

            return res.redirect("/dashboard");
        }

        // ❌ Failed login → brute force tracking
        loginAttempts[username] = (loginAttempts[username] || 0) + 1;

        if (loginAttempts[username] >= 3) {
    console.log("Brute force detected!");

    // STEP 1: initialize session
    if (!req.session.solved) {
        req.session.solved = [];
    }

    // STEP 2: push only if not exists
    if (!req.session.solved.includes('bruteforce')) {
        req.session.solved.push('bruteforce');
    }

    console.log("UPDATED SESSION:", req.session.solved);

    // STEP 3: redirect
    return res.redirect("/report?type=bruteforce");
}

        return res.render("login", { error: "Invalid credentials" });

    });
});

router.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});
router.get('/reset', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log("Reset error:", err);
            return res.send("Error resetting lab");
        }
        res.redirect('/report');
    });
});

router.get('/completed', (req, res) => {
    if (!req.session.solved || req.session.solved.length < 5) {
        return res.redirect('/dashboard'); // prevent cheating
    }

    res.render('completed');
});
module.exports = router;