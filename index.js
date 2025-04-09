import express from "express";
import cors from "cors";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { isUserLoggedIn } from "./middlewares/auth.js";
dotenv.config();
import mysql from "mysql2/promise";


const conn = await mysql
  .createConnection({
    port: process.env.MYSQL_PORT,
    host: process.env.MYSQL_HOST_NAME,
    user: process.env.MySQL_USER,
    password: process.env.MySQL_PASSWORD,
    database: process.env.MySQL_DB_NAME,
  });

const app = express();
const port = process.env.PORT;
const jwt_secret = process.env.JWT_SECRET;

app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

app.get("/", (req, res) => {
  return res.send("Welcome to Edtech trainig");
});

app.post("/register", async (req, res) => {
  try {
    // const username = req.body.username;
    // const email = req.body.email;
    // const password = req.body.password;

    //alternative
    const { username, email, password } = req.body;

    // check if the user with username exist
    const existUsernameQuery = `SELECT * FROM user WHERE username=?`;

    const [rows] = await conn.query(existUsernameQuery, [
      username.toLowerCase(),
    ]);
    const existUsername = rows[0];

    if (existUsername) {
      return res
        .status(409)
        .json({ message: "username already taken, try another one" });
    }

    const existEmailQuery = `SELECT * FROM user WHERE email=?`;
    const [rowsEmail] = await conn.query(existEmailQuery, [email]);
    const existEmail = rowsEmail[0];

    if (existEmail) {
      return res
        .status(409)
        .json({ message: "email already taken, try another one" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // insert the user
    const inserQuery =
      "INSERT INTO user (username, email, password) VALUES (?, ?, ?)";
    const [result] = await conn.query(inserQuery, [
      username.toLowerCase(),
      email,
      hashedPassword,
    ]);

    const insertedQuery = "SELECT * FROM user WHERE id=?";
    const [insertedUser] = await conn.query(insertedQuery, [result.insertId]);

    return res.status(201).json({
      message: "Account created successfully",
      userData: insertedUser[0],
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/users", isUserLoggedIn, async (req, res) => {
  try {
    const query = "select * from user;";
    const [rows] = await conn.query(query);
    return res.status(200).json({
      message: "All users",
      users: rows,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/users/count", async (req, res) => {
  try {
    const query = "SELECT COUNT(*) AS count FROM user;";
    const [result] = await conn.query(query);
    const userCount = result[0].count;
    return res.status(200).json({
      message: "Total number of users",
      number_of_users: userCount,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});

//Retrive a single user by id using params
app.get("/users/:user_id", async (req, res) => {
  try {
    const userId = parseInt(req.params.user_id);
    const query = "SELECT * FROM user WHERE id=?";
    const [result] = await conn.query(query, [userId]);
    const user = result[0];

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }
    return res.status(200).json({
      user: user,
      message: "Oparation successful",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});

// Update user
app.put("/users/:user_id", async (req, res) => {
  try {
    const userId = parseInt(req.params.user_id);
    const { username } = req.body;

    // check if the user with username exist
    const existUsernameQuery = `SELECT * FROM user WHERE username=?`;

    const [rows] = await conn.query(existUsernameQuery, [
      username.toLowerCase(),
    ]);
    const existUsername = rows[0];

    if (existUsername) {
      return res.status(409).json({ message: "username already taken" });
    }

    const updateQuery = "UPDATE user SET username=? WHERE id=?";
    const [result] = await conn.query(updateQuery, [username.toLowerCase(), userId]);
    if(result.affectedRows===0){
      return res.status(404).json({message: "User not found"});
    }
    const updatedUserQuery = "SELECT * FROM user WHERE id=?";
    const [updatedUser] = await conn.query(updatedUserQuery,[userId])

    return res.status(200).json({
      message: "username updated successfully",
      updatedUser:updatedUser[0],
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.delete("/users/:user_id", async (req, res)=>{
    try {
        const userId = parseInt(req.params.user_id);
        const deleteQuery= "DELETE FROM user WHERE id=?";
        const [result] = await conn.query(deleteQuery, [userId]);

        if(result.affectedRows === 0){
            return res.status(404).json({message: "User not found"})
        }
        

        return res.status(200).json({message: "User deleted"});

    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error"})
    }
});

app.post("/login", async (req, res)=>{
  try {
    const { email, password } = req.body;

    // find the user in the database
    const query = "SELECT * FROM user WHERE email=?";
    const [result] = await conn.query(query, [email]);
    const user = result[0];

    // if the user if not found in the database, we return unauthorised response
    if(!user){
      return res.status(401).json({
        message: "Invalid credentials"
      })
    }

    // compare the password
    const isPasswordCorrect = await bcrypt
    .compare(password, user.password);

    //if the password provided is incorrect,
    //  return unauthorised response
    if(!isPasswordCorrect){
      return res.status(401).json({
        message: "Invalid credentials"
      })
    }

    // if password d correct, we generate the token
    const token = jwt.sign({id: user.id}, jwt_secret, {expiresIn: "1h"});

    return res.status(200).json({
      message: "Login successful",
      token,
      user,
    })

  } catch (error) {
    console.log(error)
    return res.status(500).json({message: "Server error"})
  }
});

app.patch("/change-password", isUserLoggedIn, async (req, res)=>{
  try {
    const {newPassword, oldPassword} = req.body;
    const user = req.user;

    //check if the provided old password matches the user password
    const isPwdCorrect = await bcrypt.compare(oldPassword, user.password);
    if(!isPwdCorrect){
      return res.status(401).json({message: "Incorrect password"})
    };

    // check if the new password id
    //  not the same as the old password
    if(newPassword === oldPassword){
      return res.status(400)
      .json({message: "New password should not be the same as the old password"})
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    const changePwdQuery = "UPDATE user SET password=? WHERE id=?";
    await conn.query(changePwdQuery, [hashedNewPassword, user.id]);

    // await prisma.user.update({
    //   where: { id: user.id},
    //   data: {
    //     password: hashedNewPassword,
    //   }
    // })

    return res.status(200).json({message: "password changed"})
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
})

app.use((req, res) => {
    return res.status(404).json({ message: "Endpoint not found" });
});

app.listen(port, () => console.log(`Server is running at ${port}`));
