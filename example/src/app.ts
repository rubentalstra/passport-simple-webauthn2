import express from "express";
import session from "express-session";
import passport from "passport";
import dotenv from "dotenv";
import authRoutes from "./routes/auth";

// Load environment variables
dotenv.config();

const app = express();
app.set("view engine", "ejs");
app.set("views", __dirname + "/views");

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: "supersecretkey",
        resave: false,
        saveUninitialized: true,
    })
);

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use("/", authRoutes);

// Home route
app.get("/", (req, res) => {
    res.render("index");
});

export default app;