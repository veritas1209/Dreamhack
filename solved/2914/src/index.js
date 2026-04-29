const express = require('express');
const path = require('path');
const authRoutes = require('./routes/auth');
const pageRoutes = require('./routes/pages');

const server = express();

server.use(express.json());
server.use(express.urlencoded({ extended: false }));
server.use('/assets', express.static(path.join(__dirname, 'public')));
server.set('view engine', 'ejs');
server.set('views', path.join(__dirname, 'views'));

server.use('/api/auth', authRoutes);
server.use('/', pageRoutes);

server.listen(3000);
