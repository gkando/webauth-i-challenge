const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs'); /// <<<<<< install it and require it

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');
const authenticate = require('./auth/authenticate-middleware.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
// server.use(authenticate); // restricts all endpoints NONO

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  // [password] + [secret] > (hashing function) > Hashed String > stored in the database
  // pass > hash > re-hash > hash > re-hash > hash > ......

  // bcrypt.hash(user.password, 8, (err, hash) => {
  //   if(err) {
  //     // handle and return out
  //   } else {
  //     // user.password = hash;
  //     // save user to DB
  //   }
  // }); // not 8 but 2 ^ 8 times (a good starting point is 14)

  const hash = bcrypt.hashSync(user.password, 8); // not 8 but 2 ^ 8 times (a good starting point is 14)
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// protect /api/users so only clients that provide valid credentials can see the list of users
// read the username and password from the headers instead of the body (can't send a body on a GET request)
server.get('/api/users', authenticate, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
