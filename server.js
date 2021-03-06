const express = require('express');
const connectDB = require('./config/db')
const app = express();
const path = require('path')
connectDB();

app.use(express.json());
app.use(express.static(path.resolve(__dirname, 'client', 'build')));
const PORT = process.env.PORT || 5000;

app.use('/api/users', require('./routes/api/users'));
app.use('/api/auth', require('./routes/api/auth'));
app.use('/api/posts', require('./routes/api/posts'));
app.use('/api/profile', require('./routes/api/profile'));
app.get('*', (req, res)=> res.sendFile(path.resolve(__dirname, 'client','build', 'index.html')));
app.listen(PORT, ()=> console.log(`Server listening on port:${PORT}`));