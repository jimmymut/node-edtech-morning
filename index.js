import express from "express";
import cors from "cors";
import morgan from "morgan";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { isUserLoggedIn } from "./middlewares/auth.js";
dotenv.config();

const app = express();
const prisma = new PrismaClient();
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
    const existUsername = await prisma.user.findUnique({
      where: {
        username: username,
      },
    });

    if (existUsername) {
      return res
        .status(409)
        .json({ message: "username already taken, try another one" });
    }

    const existEmail = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (existEmail) {
      return res
        .status(409)
        .json({ message: "email already taken, try another one" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: {
        username: username,
        email: email,
        password: hashedPassword,
      },
    });

    return res.status(201).json({
      message: "Account created successfully",
      userData: newUser,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    return res.status(200).json({
      message: "All users",
      users: users,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});
app.get("/count user", async (req, res) => {
  try {
    const userCount = await prisma.user.count();
    return res.status(200).json({
      message: "All users",
      users: users,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
});

app.get("/users/count", async (req, res)=>{
    try {
        const userCount = await prisma.user.count();
        return res.status(200).json({
            message: "Total number of users",
            number_of_users: userCount,
            
        })
        
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error"})
        
    }
});

//Retrive a single user by id using params
app.get("/users/:user_id", async(req, res)=>{
    try {
        const userId = parseInt(req.params.user_id);
        const user = await prisma.user.findUnique({
            where: { id: userId}
        });

        if(!user){
            return res.status(404).json({
                message: "User not found"
            })
        }
        return res.status(200).json({
            user: user,
            message: "Oparation successful"
        });
        
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error"})
    }
});

// Update user
app.put("/users/:user_id", async(req, res)=>{
    try {
        const userId = parseInt(req.params.user_id);
        const { username } = req.body;
        const existUsername = await prisma.user.findUnique({
            where: {username}
        });
        if(existUsername){
            return res.status(409).json({ message: "username already taken"})
        }
        const updatedUser = await prisma.user.update({
            where: {id: userId},
            data:{
                username: username,
            }
        });

        return res.status(200).json({
            message: "username updated successfully",
            updatedUser
        })

        
    } catch (error) {
        console.log(error)
        return res.status(500).json({message: "Server error"})
    };
});

app.delete("/users/:user_id", async (req, res)=>{
    try {
        const userId = parseInt(req.params.user_id);
        const checkExist = await prisma.user.findFirst({
            where: {id: userId}
        });
        if(!checkExist){
            return res.status(404).json({message: "User not found"})
        }
        await prisma.user.delete({
            where: { id: userId }
        })

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
    const user = await prisma.user
    .findUnique({
      where: {email}
    });

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
    await prisma.user.update({
      where: { id: user.id},
      data: {
        password: hashedNewPassword,
      }
    })

    return res.status(200).json({message: "password changed"})
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Server error" });
  }
})



// app.all("*", (req, res) => {
//     return res.status(404).json({ message: "Endpoint not found" });
// });

prisma
  .$connect()
  .then(() => console.log("Database connected"))
  .catch((err) => {
    console.log(err);
    process.exit(1);
  });
app.listen(port, () => console.log(`Server is running at ${port}`));
