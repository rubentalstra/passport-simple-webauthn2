// app.ts
import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import router from './routes/auth'; // Adjust the path as necessary
dotenv.config();

const app = express();

// Set up view engine (e.g., EJS, Pug, etc.)
// app.set('views', path.join(__dirname, './views'));
app.set('views', path.join(__dirname, '../src/views')); // Points to src/views
app.set('view engine', 'ejs'); // Replace 'ejs' with your preferred view engine

// Use the router
app.use('/', router);

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});