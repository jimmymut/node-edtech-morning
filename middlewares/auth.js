import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
import mysql from "mysql2/promise";

const connection = await mysql
  .createConnection({
    port: process.env.MYSQL_PORT,
    host: process.env.MYSQL_HOST_NAME,
    user: process.env.MySQL_USER,
    password: process.env.MySQL_PASSWORD,
    database: process.env.MySQL_DB_NAME,
  });


const secret = process.env.JWT_SECRET;

export const isUserLoggedIn = async (req, res, next)=>{
try {
    const authorization = req.headers.authorization;
    if(!authorization){
        return res.status(401).json({message: "Unauthorized"})
    }
    const tokenArr = authorization.split(" ");
    const token = tokenArr[1];

    // verify the token
    const tokenData = jwt.verify(token, secret);

    // check if the user exist in database
    const query = "SELECT * FROM user WHERE id=?";

    const [result] = await connection.query(query, [tokenData.id]);
    const user = result[0];
    // if user if not found
    if(!user){
        return res.status(401).json({message: "Unauthorized"})
    }
    req.user = user;
    next();
} catch (error) {
    console.log(error);
    return res.status(400).json({ message: error.message });
}

}