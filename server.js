const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./database.json');
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'));

server.use(bodyParser.urlencoded({extended: true}));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789';

const expiresIn = '1h';

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, {expiresIn});
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err,
  );
}

// Check if the user exists in database
function isAuthenticated({username, password}) {
  return (
    userdb.users.findIndex(
      user => user.username === username && user.password === password,
    ) !== -1
  );
}

// Register New User
server.post('/auth/register', (req, res) => {
  console.log('register endpoint called; request body:');
  console.log(req.body);
  const {username, password} = req.body;

  if (isAuthenticated({username, password}) === true) {
    const status_code = 401;
    const message = 'Email and Password already exist';
    res.status(status_code).json({status_code, message});
    return;
  }

  fs.readFile('./users.json', (err, data) => {
    if (err) {
      const status_code = 401;
      const message = err;
      res.status(status_code).json({status_code, message});
      return;
    }

    // Get current users data
    var data = JSON.parse(data.toString());

    // Get the id of last user
    var last_item_id = data.users[data.users.length - 1].id;

    //Add new user
    data.users.push({
      id: last_item_id + 1,
      username: username,
      password: password,
    }); //add some data
    var writeData = fs.writeFile(
      './users.json',
      JSON.stringify(data),
      (err, result) => {
        // WRITE
        if (err) {
          const status_code = 401;
          const message = err;
          res.status(status_code).json({status_code, message});
          return;
        }
      },
    );
  });

  // Create token for new user
  const access_token = createToken({username, password});
  console.log('Access Token:' + access_token);
  res.status(200).json({access_token});
});

// Login to one of the users from ./users.json
server.post('/auth/login', (req, res) => {
  console.log('login endpoint called; request body:');
  console.log(req.body);
  const {username, password} = req.body;
  if (isAuthenticated({username, password}) === false) {
    const status_code = 401;
    const message = 'Incorrect username or password';
    res.status(status_code).json({status_code, message});
    return;
  }
  const access_token = createToken({username, password});
  console.log('Access Token:' + access_token);
  res.status(200).json({access_token, user: 1});
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(' ')[0] !== 'Bearer'
  ) {
    const status_code = 401;
    const message = 'Error in authorization format';
    res.status(status_code).json({status_code, message});
    return;
  }
  try {
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

    if (verifyTokenResult instanceof Error) {
      const status_code = 401;
      const message = 'Access token not provided';
      res.status(status_code).json({status_code, message});
      return;
    }
    next();
  } catch (err) {
    const status_code = 401;
    const message = 'Error access_token is revoked';
    res.status(status_code).json({status_code, message});
  }
});

server.use(router);

server.listen(8000, () => {
  console.log('Run Auth API Server');
});
