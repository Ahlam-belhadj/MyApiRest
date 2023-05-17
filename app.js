const express = require("express");
const dotenv = require("dotenv");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

dotenv.config({ path: "./.env" });
const app = express();

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE
});

db.connect((error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Connection successful");
  }
});

app.use(express.json());

// Generate JWT token
function generateToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role,
  };

  const options = {
    expiresIn: process.env.JWT_EXPIRES_IN
  };

  return jwt.sign(payload, process.env.JWT_SECRET, options);
}

//Verification de token
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "Access denied. Token missing." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
    if (error) {
      return res.status(401).json({ error: "Invalid token." });
    }

    req.user = decoded;
    next();
  });
}

//creation d'utilisateur
app.post("/user", (req, res) => {
  const { name, password, role, email } = req.body;

  bcrypt.hash(password, 10, (error, hashedPassword) => {
    if (error) {
      console.log(error);
      res.status(500).json({ error: "Operation failed" });
    } else {
      const newUser = { name, password: hashedPassword, role, email };
      db.query("INSERT INTO users SET ?", newUser, (error, result) => {
        if (error) {
          console.log(error);
          res.status(500).json({ error: "Operation failed" });
        } else {
          const user = { id: result.insertId, ...newUser };
          const token = generateToken(user);
          res.status(201).json({
            message: "User created successfully",
            token: token,
          });
        }
      });
    }
  });
});



//login 
app.post('/login', (req, res) => {

  const { email , password } = req.body;

  db.query ('SELECT * FROM users WHERE email = ?' , email, (error , result) => {
    if (error) {
      console.log(error);
      res.status(500).json({ error: 'Failed to login'})
    }else if (result.length === 0){
      res.status(401).json({ error: 'Invalid email or password'})
    } else {
      const user = result[0]
      bcrypt.compare(password, user.password, (error, isMatch) => {
        if(error){
          console.log(error)
          res.status(500).json({ error: 'Failed to login'})
        } else if (isMatch){
          const token = generateToken(user)
          res.status(200).json({
            message: "Login sucessful",
            token: token,
          });
        }
      })
    }
  })
})


//afficher tout les utilisateurs
app.get('/users', (req, res) => {
  db.query('SELECT * FROM users', (error , results) => {
    if (error){
      console.log(error);
      res.status(500).json({ error: ' Failed to retrieve users'});
    }else {
      res.status(200).json(results)
    }
  })
})

//afficher un utilisateur
app.get('/users/:id', (req, res) => {
  const userId = req.params.id
  console.log(userId);

  db.query('SELECT * FROM users WHERE id = ?', userId, (error, results) => {
    if(error) {
      console.log(error);
      res.status(500).json({ error: 'Failed to retrieve the user '})
    } else if (results.length === 0) {
      res.status(404).json({ error: 'Use not found'});
    }else {
      res.status(200).json(results[0]);
    }
  })
})


//update
app.put('/users/:id', (req, res) => {
  const userId = req.params.id;
  const { name, password, role, email} = req.body;
  const updateUser = { name, password, role , email}; 
  console.log(userId);

  db.query( 'UPDATE users SET ? WHERE id = ?', 
  [updateUser, userId], 
  (error, result) => {
    if (error ) {
      console.log(error);
      res.status(500).json({ error: 'Failed to update the user'})
    } else if (result.affectedRows === 0) {
      res.status(404).json({ error: 'User not found'});
    } else {
      res.status(200).json({ message: 'User updated successfully'});
    }
})
})

app.delete('/users/:id', (req, res) => {
  const userId = req.params.id;

  db.query('DELETE FROM users WHERE id = ?', userId, (error, results) => {
    if(error) {
      console.log(error);
      res.status(500).json({ error: 'Failed to retrieve the user '})
    } else if (results.length === 0) {
      res.status(404).json({ error: 'Use not found'});
    }else {
      res.status(200).json(results[0]);
    }
  })
})


// 
app.listen(3002, () => {
  console.log('Server running in port 3002');
})