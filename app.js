const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");
const db = require("./config/db");

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "vaptlab",
    resave: false,
    saveUninitialized: true
  })
);

// View engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use("/",require("./routes/authRoutes"));

// Server start
const PORT = 3000;
// Show login page
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});
app.post("/register", (req, res) => {
    const { username, password, email } = req.body;

    // Weak password detection
    if (password.length < 6) {
        return res.redirect("/report?type=weak");
    }

    const sql = "INSERT INTO users (username, password, email) VALUES (?, ?, ?)";
    db.query(sql, [username, password, email], (err) => {
        if (err) throw err;
        res.redirect("/login");
    });
});
app.post("/login", (req, res) => {

    const { username, password } = req.body;
if (!req.session.bruteforceAttempts) {
    req.session.bruteforceAttempts = [];
}

req.session.bruteforceAttempts.push(password);
    if (password.length < 6) {
        console.log("Weak password detected!");
        return res.redirect("/report?type=weak");
    }

    if (
        username.includes("'") ||
        username.toLowerCase().includes("or") ||
        username.includes("--")
    ) {
        console.log("SQL Injection detected!");
        return res.redirect("/report?type=sqli");
    }

    const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

    db.query(sql, (err, result) => {
        if (err) throw err;

        if (result.length > 0) {
          req.session.user = result[0];
          console.log("USER SET:", result[0]);
            res.redirect("/dashboard");
        } else {
            return res.render("login", { error: "Invalid credentials" });
        }
    });

});

app.get("/dashboard", (req, res) => {
  console.log("SESSION USER:", req.session.user);
  res.render("dashboard", {user:req.session.user});
});
app.get('/account', (req, res) => {
  res.render('account', { user: req.session.user || {} });
});
app.get("/products", (req, res) => {
  res.render("products");
});
app.get("/profile", (req, res) => {

    // ✅ Step 1: Check login
    if (!req.session.user) {
        return res.redirect("/login");
    }

    const sessionId = req.session.user.id;
    const queryId = req.query.id;

    console.log("queryId:", queryId);
    console.log("sessionId:", sessionId);

    // ✅ Step 2: IDOR detection (ONLY when user tries to tamper)
    if (queryId && queryId != sessionId) {
        console.log("IDOR detected!");
        return res.redirect("/report?type=idor");
    }

    // ✅ Step 3: Always use session ID (safe)
    const sql = `SELECT * FROM users WHERE id='${sessionId}'`;

    db.query(sql, (err, result) => {
        if (err) throw err;

        if (result.length > 0) {
            res.render("account", { user: result[0] });
        } else {
            res.send("User not found");
        }
    });

});
app.get("/completed", (req, res) => {
    res.render("completed");
});
app.get("/feedback", (req, res) => {

  res.render("feedback",{message:""});
});
app.post("/feedback", (req, res) => {
  const { name, email, message } = req.body;

  if(message.includes("<script>")){
    console.log("XSS detected!");
    return res.redirect("/report?type=xss");
}

  console.log("Feedback received:");
  console.log(name, email, message);

  res.send(`Feedback received: ${message}`);
});

let solvedLabs = [];

app.get("/report", (req, res) => {
    const type = req.query.type;
    let progress = req.session.progress || 0;

// Increase progress when a vulnerability is triggered
if (type) {
    progress += 1;
    req.session.progress = progress;
}

// 🔥 IMPORTANT: check completion
if (progress >= 5) {
    return res.redirect("/completed");
}

    // add solved lab automatically
    if (type && !solvedLabs.includes(type)) {
        solvedLabs.push(type);
    }

    res.render("report", { type, solved: solvedLabs });
});
app.get("/reset", (req, res) => {
    solvedLabs = [];
    res.redirect("/report");
});
app.get("/admin", (req, res) => {

    db.query("SELECT * FROM users", (err, users) => {
        if (err) throw err;

        db.query("SELECT * FROM feedback", (err, feedback) => {
            if (err) throw err;

            db.query("SELECT COUNT(*) AS totalProducts FROM products", (err, result) => {
                if (err) throw err;

                const totalProducts = result[0].totalProducts;

                db.query("SELECT * FROM products", (err, products) => {
    if (err) throw err;

    res.render("admin", {
        users,
        feedback,
        products,
        totalUsers: users.length,
        totalFeedback: feedback.length,
        totalProducts,
        products

    });
});

               
                });
            });
        });
    });

app.get("/delete/:id", (req, res) => {
    const id = req.params.id;

    const sql = `DELETE FROM users WHERE id='${id}'`;

    db.query(sql, (err, result) => {
        if (err) throw err;

        res.redirect("/admin");
    });
});
app.get("/delete-product/:id", (req, res) => {
    const id = req.params.id;

    db.query("DELETE FROM products WHERE id = ?", [id], (err) => {
        if (err) throw err;
        res.redirect("/admin");
    });
});
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});